use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use crossbeam_channel::{unbounded, Sender, Receiver};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read as StdRead, Write as StdWrite};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Pull in zmodem2's symbols
use zmodem2::{
    receive as zmodem_recv_step, send as zmodem_send_step, Error as ZError, Read as ZRead,
    Seek as ZSeek, Stage as ZStage, State as ZState, Write as ZWrite,
};


/// Enum representing commands that can be sent to the serial port handler
enum SerialCommand {
    Write(String),
    SendZmodem(String),    // Path to send
    ReceiveZmodem(String), // Destination path
    Quit,
}

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

    let mut maybe_port: Option<Box<dyn SerialPort + Send>> = None;
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
                    if let Err(e) = init_modem(port) {
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
                    if let Some(port) = maybe_port.take() {
                        let _ = dial_number(port, phone_number); // Pass the Box directly
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
                if let Some(port) = maybe_port.take() { // Take ownership out of maybe_port
                    let _ = answer_call(port);
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
        .timeout(Duration::from_millis(500))
        .data_bits(DataBits::Eight)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .flow_control(FlowControl::Hardware)
        .open()?;
    Ok(port)
}

/// Send typical AT commands to reset the modem and ensure V.92 is enabled.
fn init_modem(port: &mut Box<(dyn SerialPort + Send)>) -> Result<(), Box<dyn Error>> {
    // Send the ATZ command to reset the modem
    std::io::Write::write_all(&mut *port, b"ATZ\r")?;
    port.flush()?; // Flush to ensure data is sent
    std::thread::sleep(Duration::from_millis(500));

    // Send the AT&F1 command to load factory settings
    std::io::Write::write_all(&mut *port, b"AT&F1\r")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(500));

    // Send the AT+MS command to configure V.92 settings
    std::io::Write::write_all(&mut *port, b"AT+MS=V92,1,300,56000,300,48000\r")?;
    port.flush()?;
    std::thread::sleep(Duration::from_millis(500));

    // Send the RTS/CTS HARDWARE flow control settings
    std::io::Write::write_all(&mut *port, b"AT+IFC=2,2\r")?; //1,1 software control.
    port.flush()?;
    std::thread::sleep(Duration::from_millis(500));

    // Read and display the modem response (optional)
    let mut buf = [0u8; 1024];
    match std::io::Read::read(&mut *port, &mut buf) {
        Ok(n) if n > 0 => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            println!("Modem response:\n{}", resp);
        }
        Ok(_) => println!("No response from modem."),
        Err(e) => eprintln!("Error reading modem response: {}", e),
    }

    Ok(())
}

/// Dials a phone number, waits for "CONNECT",
/// parses the speed, then calls `chat_loop`.
fn dial_number(
    mut port: Box<dyn SerialPort + Send>,
    phone_number: &str,
) -> Result<(), Box<dyn Error>> {

    // 1) Send dial command
    let cmd = format!("ATD{}\r", phone_number);
    std::io::Write::write_all(&mut *port, cmd.as_bytes())?;

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
                    println!("/send filename");
                    println!("/receive");
                    println!("/quit");
                    // Now jump into chat mode
                    chat_loop(port);
                    break; // exit function
                }

                // You might also handle "BUSY", "NO CARRIER", etc. here.
            }
            Err(_e) => {
                eprintln!("Please Wait... ");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

fn answer_call(mut port: Box<dyn SerialPort + Send>) -> Result<(), Box<dyn Error>> {
    // 1) Tell modem to auto-answer on the first ring
    let _ = std::io::Write::write_all(&mut *port, b"ATS0=1\r");

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
                    println!("Entered CHAT mode!");
                    println!("/send filename");
                    println!("/receive");
                    println!("/quit");
                    chat_loop(port); // Pass ownership to chat_loop
                    break;
                }
            }
            Err(_e) => {
                eprintln!("Please Wait... ");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

/// Function to handle chat operations with the modem.
/// This function sets up a dedicated serial port handler thread, along with reader and writer threads.
/// It uses message passing via channels to avoid Mutex lock contention.
fn chat_loop(port: Box<dyn SerialPort + Send>) {
    // Create channels for communication
    let (cmd_sender, cmd_receiver): (Sender<SerialCommand>, Receiver<SerialCommand>) = unbounded();
    let (data_sender, data_receiver): (Sender<String>, Receiver<String>) = unbounded();

    // Atomic flag to indicate whether the application is running
    let running = Arc::new(AtomicBool::new(true));

    // Clone references for the serial port handler thread
    let running_handler = Arc::clone(&running);
    let cmd_receiver_handler = cmd_receiver.clone();
    let data_sender_handler = data_sender.clone();

    // Spawn the serial port handler thread
    let serial_handler = thread::spawn(move || {
        let mut port = port;

        loop {
            // Check if we should terminate
            if !running_handler.load(Ordering::SeqCst) {
                println!("Serial Handler: Shutting down.");
                break;
            }

            // Handle incoming commands
            match cmd_receiver_handler.try_recv() {
                Ok(cmd) => {
                    match cmd {
                        SerialCommand::Write(msg) => {
                            if let Err(e) = writeln!(port, "{}", msg) {
                                eprintln!("Serial Handler: Error writing to modem: {}", e);
                            }
                            if let Err(e) = port.flush() {
                                eprintln!("Serial Handler: Error flushing port: {}", e);
                            }
                        }
                        SerialCommand::SendZmodem(path) => {
                            if let Err(e) = zmodem2_send(port.as_mut(), &path) {
                                eprintln!("Serial Handler: ZMODEM2 send error: {}", e);
                            }
                        }
                        SerialCommand::ReceiveZmodem(dest) => {
                            if let Err(e) = zmodem2_recv(port.as_mut(), &dest) {
                                eprintln!("Serial Handler: ZMODEM2 receive error: {}", e);
                            }
                        }
                        SerialCommand::Quit => {
                            println!("Serial Handler: Quit command received.");
                            running_handler.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {
                    // No commands to process, continue
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    println!("Serial Handler: Command channel disconnected.");
                    break;
                }
            }

            // Read data from the serial port
            let mut buf = [0u8; 1024];
            match std::io::Read::read(&mut port, &mut buf) {
                Ok(n) if n > 0 => {
                    // Convert bytes to string
                    match String::from_utf8(buf[..n].to_vec()) {
                        Ok(s) => {
                            // Send the received data to the data_receiver
                            if let Err(e) = data_sender_handler.send(s) {
                                eprintln!("Serial Handler: Error sending data to receiver: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Serial Handler: Received invalid UTF-8 data: {}", e);
                        }
                    }
                }
                Ok(_) => {
                    // No data received, continue
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Read timed out, continue
                }
                Err(e) => {
                    eprintln!("Serial Handler: Error reading from modem: {}", e);
                    break;
                }
            }

            // Sleep briefly to prevent tight looping
            thread::sleep(Duration::from_millis(10));
        }

        println!("Serial Handler: Exiting.");
    });

    // Clone the data receiver for the reader thread
    let data_receiver_clone = data_receiver.clone();
    let running_clone_reader = Arc::clone(&running);

    // Spawn the reader thread to handle incoming data
    let reader_handle = thread::spawn(move || {
        while running_clone_reader.load(Ordering::SeqCst) {
            match data_receiver_clone.recv_timeout(Duration::from_millis(100)) {
                Ok(data) => {
                    println!("(modem) {}", data.trim_end());
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // No data received within timeout, continue
                }
                Err(_) => {
                    // Channel disconnected
                    break;
                }
            }
        }
        println!("Reader thread: Exiting.");
    });

    // Clone the command sender for the writer thread
    let cmd_sender_clone = cmd_sender.clone();
    let running_clone_writer = Arc::clone(&running);

    // Spawn the writer thread to handle user input
    let writer_handle = thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin_lock = stdin.lock();
        let mut input = String::new();

        while running_clone_writer.load(Ordering::SeqCst) {
            print!("> "); // Prompt for user input
            io::stdout().flush().expect("Failed to flush stdout");

            input.clear();
            match stdin_lock.read_line(&mut input) {
                Ok(n) => {
                    if n == 0 {
                        // EOF reached
                        break;
                    }

                    let trimmed = input.trim_end().to_string();

                    if trimmed.starts_with("/send ") {
                        let path = trimmed.strip_prefix("/send ").unwrap().trim().to_string();
                        if !path.is_empty() {
                            if let Err(e) = cmd_sender_clone.send(SerialCommand::SendZmodem(path)) {
                                eprintln!("Writer thread: Error sending ZMODEM2 send command: {}", e);
                            }
                        } else {
                            println!("Usage: /send <file_path>");
                        }
                    } else if trimmed == "/receive" {
                        let destination = ".".to_string(); // Current directory
                        if let Err(e) = cmd_sender_clone.send(SerialCommand::ReceiveZmodem(destination)) {
                            eprintln!("Writer thread: Error sending ZMODEM2 receive command: {}", e);
                        }
                    } else if trimmed == "/quit" {
                        if let Err(e) = cmd_sender_clone.send(SerialCommand::Quit) {
                            eprintln!("Writer thread: Error sending Quit command: {}", e);
                        }
                        break; // Exit the loop
                    } else {
                        // Send raw input to the modem
                        if let Err(e) = cmd_sender_clone.send(SerialCommand::Write(trimmed.clone())) {
                            eprintln!("Writer thread: Error sending write command: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Writer thread: Error reading from stdin: {}", e);
                    break;
                }
            }
        }

        println!("Writer thread: Exiting.");
    });

    // Wait for the application to terminate gracefully
    // This loop keeps the main thread alive until the running flag is set to false
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    // Wait for the handler thread to finish
    serial_handler.join().unwrap_or_else(|e| {
        eprintln!("Main thread: Serial handler thread panicked: {:?}", e);
    });

    // Wait for the reader thread to finish
    reader_handle.join().unwrap_or_else(|e| {
        eprintln!("Main thread: Reader thread panicked: {:?}", e);
    });

    // Wait for the writer thread to finish
    writer_handle.join().unwrap_or_else(|e| {
        eprintln!("Main thread: Writer thread panicked: {:?}", e);
    });

    println!("Main thread: Chat terminated.");
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
        self.port.write_all(buf).map_err(|e| map_io_err(e))?;
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
            Err(_) => Err(ZError::Read), // Or ZError::Data if you like
        }
    }

    fn read_byte(&mut self) -> Result<u8, ZError> {
        let mut single = [0u8; 1];
        self.inner
            .read_exact(&mut single)
            .map_err(|_| ZError::Read)?;
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
        self.inner.seek(offset.into()).map_err(|_| ZError::Read)?;
        Ok(())
    }
}

// --------------------------------------------------------------------
// ZMODEM2: Synchronous "send" wrapper
// --------------------------------------------------------------------

/// Send a file using the zmodem2 crate in a loop until the transfer is `Done`.
fn zmodem2_send(
    port: &mut dyn SerialPort,
    file_path: &str,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
    if !path.exists() || !path.is_file() {
        return Err(format!("Not a valid file: {}", file_path).into());
    }

    let size = std::fs::metadata(path)?.len();
    let size_u32 = u32::try_from(size).unwrap_or(u32::MAX);

    // Open the file for reading
    let file = File::open(path)?;
    let mut file_wrapper = LocalFile { inner: file };

    // Create a ZMODEM2 state with the file name and size
    let mut state =
        ZState::new_file(file_path, size_u32).map_err(|_| "Failed to create ZMODEM2 State")?;

    let mut zport = ZPort {
        port: port,
    };

    println!("Sending '{}' ({} bytes) via ZMODEM2...", file_path, size);

    // Keep calling `zmodem2::send()` until `Stage == Done`
    loop {
        zmodem_send_step(&mut zport, &mut file_wrapper, &mut state)
            .map_err(|e| format!("ZMODEM2 send step error: {:?}", e))?;

        if state.stage() == ZStage::Done {
            println!("File '{}' sent successfully!", file_path);
            break;
        }

        // Short sleep to avoid tight looping and allow other tasks to proceed
        std::thread::sleep(std::time::Duration::from_millis(50));
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
fn zmodem2_recv(
    port: &mut dyn SerialPort,
    output_dir: &str,
) -> Result<(), Box<dyn Error>> {
    let mut state = ZState::new(); // start with an empty (no-file) state
    let mut maybe_out_file: Option<LocalFile> = None;

    let mut zport = ZPort {
        port: port,
    };

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
        if let Some(ref mut out_file) = maybe_out_file {
            let result = zmodem_recv_step(&mut zport, out_file, &mut state);

            // If an error occurs, break out
            if let Err(e) = result {
                return Err(format!("ZMODEM2 receive error: {:?}", e).into());
            }

            // If done, exit loop
            if state.stage() == ZStage::Done {
                println!("File '{}' received successfully!", state.file_name());
                break;
            }
        } else {
            // Wait briefly for ZMODEM protocol to provide more data
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    Ok(())
}
