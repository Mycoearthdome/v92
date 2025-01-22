use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::io::{self, BufRead, BufReader, Read as StdRead, Write as StdWrite};
use std::time::Duration;
use std::fs::File;
use std::path::Path;
use std::error::Error;
use std::thread;


// Pull in zmodem2's symbols
use zmodem2::{
    send as zmodem_send_step,
    receive as zmodem_recv_step,
    State as ZState,
    Stage as ZStage,
    Error as ZError,
    Read as ZRead,
    Write as ZWrite,
    Seek as ZSeek,
};


/// Main entry point: run a simple shell for V.92 + ZMODEM2.
fn main() -> Result<(), Box<dyn Error>> {
    println!("=== V.92 Modem Chat + ZMODEM2 File-Transfer Example ===");
    println!("Commands:");
    println!("  setport <path>   - set serial port (e.g., COM3 or /dev/ttyUSB0)");
    println!("  init             - initialize modem (V.92, etc.)");
    println!("  dial <number>    - dial a phone number");
    println!("  answer           - answer incoming call (ATA)");
    println!("  quit             - exit program");
    println!();

    let mut maybe_port: Option<Box<dyn SerialPort>> = None;
    let stdin = io::stdin();

    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut cmd_line = String::new();
        if stdin.lock().read_line(&mut cmd_line).is_err() {
            break; // Input fails => exit
        }
        let cmd_line = cmd_line.trim();
        if cmd_line.is_empty() {
            continue;
        }

        let mut parts = cmd_line.split_whitespace();
        let command = parts.next().unwrap_or("");

        match command {
            "setport" => {
                if let Some(port_path) = parts.next() {
                    match open_modem_port(port_path, 115_200) {
                        Ok(port) => {
                            println!("Opened serial port: {}", port_path);
                            maybe_port = Some(port);
                        }
                        Err(e) => eprintln!("Failed to open port: {}", e),
                    }
                } else {
                    eprintln!("Usage: setport <path>");
                }
            }

            "init" => {
                // Initialize the modem in V.92 mode
                if let Some(ref mut port) = maybe_port {
                    if let Err(e) = init_modem(&mut **port) {
                        eprintln!("Modem init error: {}", e);
                    } else {
                        println!("Modem initialized.");
                    }
                } else {
                    eprintln!("No serial port is open. Use 'setport' first.");
                }
            }

            "dial" => {
                // Dial a phone number
                if let Some(phone_number) = parts.next() {
                    if let Some(ref mut port) = maybe_port {
                        let _ = dial_number(&mut **port, phone_number);
                        println!("Dialing {}...", phone_number);
                    } else {
                        eprintln!("No serial port is open. Use 'setport' first.");
                    }
                } else {
                    eprintln!("Usage: dial <phone_number>");
                }
            }

            "answer" => {
                // Answer an incoming call
                if let Some(ref mut port) = maybe_port {
                    let _ = answer_call(&mut **port);
                    println!("Answering...");
                } else {
                    eprintln!("No serial port is open. Use 'setport' first.");
                }
            }

            "quit" => {
                println!("Exiting.");
                break;
            }

            _ => {
                eprintln!("Unknown command: '{}'", command);
            }
        }
    }

    Ok(())
}

/// Open a serial port with standard 8N1 and the given baud rate.
fn open_modem_port(port_name: &str, baud_rate: u32) -> Result<Box<dyn SerialPort>, Box<dyn Error>> {
    let port = serialport::new(port_name, baud_rate)
        .timeout(Duration::from_millis(2000))
        .data_bits(DataBits::Eight)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .flow_control(FlowControl::None)
        .open()?;
    Ok(port)
}

/// Send typical AT commands to reset the modem and ensure V.92 is enabled.
fn init_modem(port: &mut dyn SerialPort) -> Result<(), Box<dyn Error>> {
    port.write_all(b"ATZ\r")?;
    std::thread::sleep(Duration::from_millis(500));

    port.write_all(b"AT&F1\r")?;
    std::thread::sleep(Duration::from_millis(500));

    port.write_all(b"AT+MS=V92,1,300,56000,300,48000\r")?;
    std::thread::sleep(Duration::from_millis(500));

    // Read and display the modem response (optional)
    let mut buf = [0u8; 1024];
    if let Ok(n) = port.read(&mut buf) {
        let resp = String::from_utf8_lossy(&buf[..n]);
        println!("Modem response:\n{}", resp);
    }
    Ok(())
}

/// Dials a phone number, waits for "CONNECT",
/// parses the speed, then calls `chat_loop`.
fn dial_number(port: &mut dyn SerialPort, phone_number: &str) -> Result<(), Box<dyn Error>> {
    // 1) Send dial command
    let cmd = format!("ATD{}\r", phone_number);
    port.write_all(cmd.as_bytes())?;

    // 2) Wrap the port in a BufReader (clone it)
    let mut reader = BufReader::new(port.try_clone()?);
    let mut response_line = String::new();

    loop {
        response_line.clear();
        match reader.read_line(&mut response_line) {
            Ok(0) => {
                // No data available right now; sleep briefly to avoid busy-looping.
                thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                // We got some data; let's see if it's CONNECT
                let trimmed = response_line.trim().to_uppercase();
                eprintln!("Modem says: {}", trimmed); // Debug logging

                if trimmed.starts_with("CONNECT") {
                    // Attempt to parse speed from something like "CONNECT 33600"
                    // or "CONNECT 50666 V92" etc.
                    let mut parts = trimmed.split_whitespace();
                    parts.next(); // skip "CONNECT"
                    if let Some(speed_str) = parts.next() {
                        // If it's purely numeric, parse as u32
                        if let Ok(speed) = speed_str.parse::<u32>() {
                            eprintln!("Dial-up connected at speed: {} bps", speed);
                        } else {
                            // Could be "50666/V92", you can split on '/' or ignore
                            eprintln!("Dial-up connected. Could not parse speed: {}", speed_str);
                        }
                    }
                    println!("Entered CHAT mode!");
                    // Now jump into chat mode
                    chat_loop(port);
                    break; // exit function
                }

                // You might also handle "BUSY", "NO CARRIER", etc. here.
            }
            Err(e) => {
                eprintln!("Error reading line: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

/// Enables auto-answer (S0=1), waits for "CONNECT",
/// parses speed, then calls `chat_loop`.
fn answer_call(port: &mut dyn SerialPort) -> Result<(), Box<dyn Error>> {
    // 1) Tell modem to auto-answer on first ring
    port.write_all(b"ATS0=1\r")?;

    // 2) Create a BufReader
    let mut reader = BufReader::new(port.try_clone()?);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No data right now
                thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                let trimmed = line.trim().to_uppercase();
                eprintln!("Modem says: {}", trimmed);

                if trimmed.starts_with("CONNECT") {
                    let mut parts = trimmed.split_whitespace();
                    parts.next(); // skip "CONNECT"
                    if let Some(speed_str) = parts.next() {
                        if let Ok(speed) = speed_str.parse::<u32>() {
                            eprintln!("Incoming call connected at speed: {} bps", speed);
                        } else {
                            eprintln!("Incoming call connected. Could not parse speed: {}", speed_str);
                        }
                    }
                    println!("Entered CHAT mode!");
                    chat_loop(port);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading line: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

/// The main chat loop.  
/// - Reads lines from stdin  
/// - Sends them to the modem.  
/// - Displays any received modem data.  
/// - Special commands for ZMODEM2: `/zsend <path>` or `/zrecv`
fn chat_loop(port: &mut dyn SerialPort) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut modem_buf = Vec::new();
    let mut input_line = String::new();

    loop {
        // 1) Attempt to read from the modem (non-blocking).
        let mut read_buf = [0u8; 256];

        match StdRead::read(&mut *port, &mut read_buf) {
            Ok(bytes_read) if bytes_read > 0 => {
                modem_buf.extend_from_slice(&read_buf[..bytes_read]);
                // Split on newline for display
                while let Some(pos) = modem_buf.iter().position(|&b| b == b'\n') {
                    let line_bytes = modem_buf.drain(..=pos).collect::<Vec<_>>();
                    let line_str = String::from_utf8_lossy(&line_bytes);
                    print!("(modem) {}", line_str);
                    stdout.flush().ok();
                }
            }
            _ => {
                // No data. We can briefly sleep or skip to avoid 100% CPU usage.
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        // 2) Check if user typed something
        if let Ok(n) = stdin.lock().read_line(&mut input_line) {
            if n > 0 {
                let trimmed = input_line.trim().to_string();
                input_line.clear(); // For next line

                if trimmed.starts_with("/send ") {
                    // /zsend <path>
                    if let Some(path) = trimmed.strip_prefix("/zsend ").map(str::trim) {
                        if !path.is_empty() {
                            if let Err(e) = zmodem2_send(&mut *port, path) {
                                eprintln!("ZMODEM2 send error: {}", e);
                            }
                        } else {
                            println!("Usage: /send <file_path>");
                        }
                    }
                } else if trimmed == "/receive" {
                    // /zrecv
                    if let Err(e) = zmodem2_recv(&mut *port, ".") {
                        eprintln!("ZMODEM2 receive error: {}", e);
                    }
                } else if trimmed == "/quit" {
                    // Exit chat
                    println!("Leaving chat mode...");
                    break;
                } else {
                    // Normal chat message
                    let _ = std::io::Write::write_all(&mut *port, trimmed.as_bytes());
                    let _ = std::io::Write::write_all(&mut *port, b"\r\n");
                }
            }
        }
    }

}

// --------------------------------------------------------------------
// Integrating zmodem2
// --------------------------------------------------------------------

/// We need to wrap `serialport::SerialPort` in a type that implements
/// `zmodem2::Read` and `zmodem2::Write` traits.
struct ZPort<'a> {
    port: &'a mut dyn SerialPort,
}

/// Map from `std::io::Error` to `zmodem2::Error`.
fn map_io_err(e: std::io::Error) -> ZError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::UnexpectedEof => ZError::Read,
        ErrorKind::BrokenPipe => ZError::Write,
        ErrorKind::TimedOut => ZError::Read,
        _ => ZError::Read, // or ZError::Write as appropriate
    }
}

impl<'a> ZRead for ZPort<'a> {
    /// `read()` tries to fill `buf` from the serial port.  
    /// Return the number of bytes read, or a zmodem2 error on failure.
    fn read(&mut self, buf: &mut [u8]) -> Result<u32, ZError> {
        match self.port.read(buf) {
            Ok(n) => Ok(n as u32),
            Err(e) => Err(map_io_err(e)),
        }
    }

    /// `read_byte()` reads exactly one byte.
    fn read_byte(&mut self) -> Result<u8, ZError> {
        let mut single = [0u8; 1];
        match self.port.read_exact(&mut single) {
            Ok(()) => Ok(single[0]),
            Err(e) => Err(map_io_err(e)),
        }
    }
}

impl<'a> ZWrite for ZPort<'a> {
    /// Write the entire buffer out to the serial port.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ZError> {
        self.port
            .write_all(buf)
            .map_err(|e| map_io_err(e))?;
        Ok(())
    }

    /// Write a single byte to the serial port.
    fn write_byte(&mut self, value: u8) -> Result<(), ZError> {
        self.write_all(&[value])
    }
}


/// A wrapper around `std::fs::File` that we can implement zmodem2 traits on.

pub struct LocalFile {
    inner: File,
}


impl LocalFile {
    // Helper to create a new file (for receiving data)
    pub fn create(path: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            inner: File::create(path)?,
        })
    }
}
// -------------------------
// Implement zmodem2::Read
// -------------------------

impl ZRead for LocalFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<u32, ZError> {
        match zmodem2::Read::read(&mut self.inner, buf) {
            Ok(n) => Ok(n as u32),
            Err(_) => Err(ZError::Read),  // Or ZError::Data if you like
        }
    }

    fn read_byte(&mut self) -> Result<u8, ZError> {
        let mut single = [0u8; 1];
        self.inner.read_exact(&mut single).map_err(|_| ZError::Read)?;
        Ok(single[0])
    }
}

// -------------------------
// Implement zmodem2::Write
// (needed for receiving files)
// -------------------------

impl ZWrite for LocalFile {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ZError> {
        zmodem2::Write::write_all(&mut self.inner, buf).map_err(|_| ZError::Write)
    }

    fn write_byte(&mut self, byte: u8) -> Result<(), ZError> {
        self.write_all(&[byte])
    }
}

// -------------------------
// Implement zmodem2::Seek
// (needed for sending if the protocol might resume at an offset)
// -------------------------

impl ZSeek for LocalFile {
    fn seek(&mut self, offset: u32) -> Result<(), ZError> {
        // Convert offset from u32 to u64
        self.inner
            .seek(offset.into())
            .map_err(|_| ZError::Read)?;
        Ok(())
    }
}


// --------------------------------------------------------------------
// ZMODEM2: Synchronous "send" wrapper
// --------------------------------------------------------------------

/// Send a file using the zmodem2 crate in a loop until the transfer is `Done`.
fn zmodem2_send(port: &mut dyn SerialPort, file_path: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
    if !path.exists() || !path.is_file() {
        return Err(format!("Not a valid file: {}", file_path).into());
    }



    let size = std::fs::metadata(path)?.len();
    let size_u32 = u32::try_from(size).unwrap_or(u32::MAX);

    // Open the file for reading
    let file = File::open(path)?;
    let mut file_wrapper = LocalFile{inner:file};

    // Create a ZMODEM2 state with the file name and size
    let mut state = ZState::new_file(file_path, size_u32)
        .map_err(|_| "Failed to create ZMODEM2 State")?;

    let mut zport = ZPort { port };

    println!("Sending '{}' ({} bytes) via ZMODEM2...", file_path, size);

    // Keep calling `zmodem2::send()` until `Stage == Done`
    loop {
        zmodem_send_step(&mut zport, &mut file_wrapper, &mut state)
            .map_err(|e| format!("ZMODEM2 send step error: {:?}", e))?;

        if state.stage() == ZStage::Done {
            println!("File '{}' sent successfully!", file_path);
            break;
        }
        // If not done, just loop again. The library uses small step calls.
    }

    Ok(())
}

// --------------------------------------------------------------------
// ZMODEM2: Synchronous "receive" wrapper
// --------------------------------------------------------------------

/// Receive a file using the zmodem2 crate, saving it to `output_dir`.
///
/// Because we won't know the filename until the first ZFILE frame arrives,
/// we create a `State::new()` and then open the file once we discover its name
/// in the subpacket.
fn zmodem2_recv(port: &mut dyn SerialPort, output_dir: &str) -> Result<(), Box<dyn Error>> {
    let mut state = ZState::new(); // start with an empty (no-file) state
    let mut maybe_out_file: Option<LocalFile> = None;

    let mut zport = ZPort { port };


    println!("Awaiting inbound ZMODEM2 file transfer...");

    loop {

        if maybe_out_file.is_none() && !state.file_name().is_empty() {
            let out_path = Path::new(output_dir).join(state.file_name());
            let f = LocalFile::create(&out_path)?; // Our wrapper that implements zmodem2::Write
            maybe_out_file = Some(f);
        
            // Now that we have the file name, we can log the "size" if it's known
            let announced_size = state.file_size();
            println!(
                "Receiving file '{}' (size = {})",
                state.file_name(),
                announced_size
            );
        }
        
        // Step the ZMODEM receive
        let result = zmodem_recv_step(&mut zport, maybe_out_file.as_mut().unwrap(), &mut state);

        // If an error occurs, break out
        if let Err(e) = result {
            return Err(format!("ZMODEM2 receive error: {:?}", e).into());
        }

        // If done, exit loop
        if state.stage() == ZStage::Done {
            println!("File '{}' received successfully!", state.file_name());
            break;
        }

        // Otherwise, keep looping to handle the next step in the protocol
    }

    Ok(())
}
