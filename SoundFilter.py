import numpy as np
import sounddevice as sd
from scipy.fft import fft
from scipy.signal import butter, sosfilt
import logging
import time
from collections import deque
import threading
import psutil  # To monitor and kill processes

# Set up logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Frequency range for human hearing (20 Hz to 20 kHz)
LOWER_CUTOFF = 20
UPPER_CUTOFF = 20000
BLOCKSIZE = 2048
SAMPLE_RATE = 44100
DELAY_SECONDS = 0.1  # Delay in seconds

# Design bandpass filter
def design_bandpass_filter(lowcut, highcut, fs, order=5):
    sos = butter(order, [lowcut, highcut], fs=fs, btype='band', output='sos')
    return sos

def bandpass_filter(data, sos):
    return sosfilt(sos, data)

# Buffer to store audio for playback with delay
audio_buffer = deque(maxlen=int(SAMPLE_RATE * DELAY_SECONDS / BLOCKSIZE))

# Function to terminate processes
def terminate_processes():
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            proc_info = proc.info
            # Here, you can add conditions to ignore certain processes if needed
            logging.info(f"Terminating process: {proc_info['name']} (PID: {proc_info['pid']})")
            proc.terminate()  # Terminate the process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logging.error(f"Failed to terminate process: {e}")

# Audio callback function
def audio_callback(indata, frames, time, status):
    if status:
        logging.debug(f"Callback status: {status}")

    # Convert audio to numpy array
    audio_data = np.squeeze(indata)
    
    # Apply bandpass filter
    filtered_audio = bandpass_filter(audio_data, sos)
    
    # Perform FFT
    fft_data = fft(filtered_audio)
    
    # Compute frequency strength (example: magnitude of the first component)
    freq_strength = np.abs(fft_data[0])
    
    # Log frequency strength
    logging.debug(f"Frequency strength: {freq_strength}")

    # Example threshold for detecting unwanted frequencies
    threshold = 50.0
    
    if freq_strength > threshold:
        logging.info("Unwanted frequency detected. Terminating processes.")
        terminate_processes()  # Terminate processes on detection
    
    # Store audio data in buffer
    audio_buffer.extend(filtered_audio)

def playback_audio():
    while True:
        if len(audio_buffer) > 0:
            # Convert buffer to numpy array
            audio_data = np.array(audio_buffer)
            sd.play(audio_data, samplerate=SAMPLE_RATE)
            sd.wait()  # Wait until the playback is finished

def start_audio_stream():
    global sos
    sos = design_bandpass_filter(LOWER_CUTOFF, UPPER_CUTOFF, SAMPLE_RATE)

    while True:
        try:
            logging.info("Starting audio stream")
            stream = sd.InputStream(callback=audio_callback, channels=1, samplerate=SAMPLE_RATE, blocksize=BLOCKSIZE)
            with stream:
                logging.info("Audio stream started, script running")
                
                # Start playback in a separate thread
                playback_thread = threading.Thread(target=playback_audio)
                playback_thread.start()
                
                # Keep the script running indefinitely
                while True:
                    time.sleep(0.1)  # Prevents excessive CPU usage in the loop
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            time.sleep(5)  # Wait before restarting

if __name__ == "__main__":
    start_audio_stream()
