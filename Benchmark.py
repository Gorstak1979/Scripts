import subprocess
import json
import time
import numpy as np
import os
import tempfile
import pyopencl as cl
import pyopencl.array as cl_array
from tkinter import Tk, Frame, Label, Button
import pyautogui
import speedtest

# CPU Benchmark using matrix multiplication
def cpu_benchmark():
    print("CPU Benchmark")
    print("-------------")
    N = 200
    A = np.random.rand(N, N)
    B = np.random.rand(N, N)

    start_time = time.time()
    for _ in range(5):
        C = np.dot(A, B)
    elapsed_time = time.time() - start_time

    gflops = (2 * N**3 / 1e9) * 5 / elapsed_time
    print(f"CPU Performance: {gflops:.2f} GFLOPS")
    return gflops

# Network Benchmark using speedtest module
def network_benchmark():
    print("\nNetwork Benchmark")
    print("-----------------")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1e6  # Convert from bps to Mbps
        upload_speed = st.upload() / 1e6  # Convert from bps to Mbps

        print(f"Download Speed: {download_speed:.2f} Mbps")
        print(f"Upload Speed: {upload_speed:.2f} Mbps")

        return {"Download Mbps": download_speed, "Upload Mbps": upload_speed}
    except Exception as e:
        print(f"Error during network benchmark: {e}")
        return None

# GPU Benchmark using OpenCL
def gpu_benchmark():
    print("\nGPU Benchmark")
    print("-------------")
    try:
        platforms = cl.get_platforms()
        device = platforms[0].get_devices()[0]
        ctx = cl.Context([device])
        queue = cl.CommandQueue(ctx)

        N = 200
        A = np.random.rand(N, N).astype(np.float32)
        B = np.random.rand(N, N).astype(np.float32)
        C = np.empty_like(A)

        mf = cl.mem_flags
        a_gpu = cl_array.to_device(queue, A)
        b_gpu = cl_array.to_device(queue, B)
        c_gpu = cl_array.to_device(queue, C)

        prg = cl.Program(ctx, """
        __kernel void matmul(__global float* a, __global float* b, __global float* c, int N) {
            int i = get_global_id(0);
            int j = get_global_id(1);
            float sum = 0;
            for (int k = 0; k < N; k++) {
                sum += a[i * N + k] * b[k * N + j];
            }
            c[i * N + j] = sum;
        }
        """).build()

        start = time.time()
        prg.matmul(queue, (N, N), None, a_gpu.data, b_gpu.data, c_gpu.data, np.int32(N))
        queue.finish()
        elapsed_time = time.time() - start
        gflops = (2 * N**3 / 1e9) / elapsed_time
        print(f"GPU Performance: {gflops:.2f} GFLOPS")
        return gflops

    except Exception as e:
        print(f"Error during GPU benchmark: {e}")
        return None

# Drive Benchmark using tempfile
def drive_benchmark():
    print("\nDrive Benchmark")
    print("---------------")
    file_size_mb = 500
    data = os.urandom(file_size_mb * 1024 * 1024)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name

        start_time = time.time()
        temp_file.write(data)
        write_time = time.time() - start_time
        write_speed = file_size_mb / write_time

    start_time = time.time()
    with open(temp_file_path, "rb") as f:
        f.read()
    read_time = time.time() - start_time
    read_speed = file_size_mb / read_time

    os.remove(temp_file_path)
    print(f"Write Speed: {write_speed:.2f} MB/s")
    print(f"Read Speed: {read_speed:.2f} MB/s")
    return {"Write MB/s": write_speed, "Read MB/s": read_speed}

# RAM Benchmark using memory-intensive operations
def ram_benchmark():
    print("\nRAM Benchmark")
    print("-------------")
    try:
        size = 500 * 1024 * 1024  # 500 MB
        start_time = time.time()
        data = bytearray(size)
        elapsed_time = time.time() - start_time
        bandwidth = size / elapsed_time / 1e9  # Convert to GB/s
        print(f"RAM Speed: {bandwidth:.2f} GB/s")
        return bandwidth
    except Exception as e:
        print(f"Error during RAM benchmark: {e}")
        return 0

# Overall Score Calculation
def calculate_overall_score(cpu_score, gpu_score, ram_score, drive_scores, network_scores):
    scores = [cpu_score, ram_score]
    if gpu_score is not None:
        scores.append(gpu_score)
    if network_scores:
        scores.append((network_scores["Download Mbps"] + network_scores["Upload Mbps"]) / 2)
    scores.append((drive_scores["Write MB/s"] + drive_scores["Read MB/s"]) / 2)
    overall_score = round(sum(scores) / len(scores), 2)
    print("\nOverall Score:", overall_score)
    return overall_score

# Function to take a screenshot
def take_screenshot():
    pyautogui.hotkey('win', 'prtscr')
    print("Screenshot taken!")

# Main function for testing
def main():
    cpu_score = cpu_benchmark()
    gpu_score = gpu_benchmark()
    ram_score = ram_benchmark()
    drive_scores = drive_benchmark()
    network_scores = network_benchmark()

    if not network_scores:
        network_scores = {"Download Mbps": 0, "Upload Mbps": 0}

    overall_score = calculate_overall_score(cpu_score, gpu_score, ram_score, drive_scores, network_scores)

    root = Tk()
    root.title("System Benchmark Results")
    root.geometry("600x400")

    frame = Frame(root, padx=20, pady=20)
    frame.pack(expand=True)

    Label(frame, text=f"CPU: {cpu_score:.2f} GFLOPS").pack()
    Label(frame, text=f"GPU: {gpu_score:.2f} GFLOPS" if gpu_score else "GPU: N/A").pack()
    Label(frame, text=f"RAM Speed: {ram_score:.2f} GB/s").pack()
    Label(frame, text=f"Drive Write: {drive_scores['Write MB/s']:.2f} MB/s").pack()
    Label(frame, text=f"Drive Read: {drive_scores['Read MB/s']:.2f} MB/s").pack()
    Label(frame, text=f"Download: {network_scores['Download Mbps']:.2f} Mbps").pack()
    Label(frame, text=f"Upload: {network_scores['Upload Mbps']:.2f} Mbps").pack()
    Label(frame, text=f"Overall Score: {overall_score:.2f}").pack()

    screenshot_button = Button(root, text="Take Screenshot", command=take_screenshot)
    screenshot_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
