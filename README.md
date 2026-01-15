# SafeGuard Backend Server

This directory contains the Python Flask backend for the SafeGuard Women Safety App.

## Prerequisites

- Python 3.x
- pip

## Setup

1. **Navigate to the backend directory:**

    ```bash
    cd "lib/Python Backend"
    ```

2. **Create/Activate Virtual Environment:**

    - **Note:** The existing `venv` folder appears to be for Windows. You should delete it and create a new one for Linux.
    - **Recreate venv:**

        ```bash
        rm -rf venv
        python3 -m venv venv
        source venv/bin/activate
        ```

3. **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Running the Server

1. **Start the server:**

    ```bash
    python app.py
    ```

2. **Verify it's running:**
    You should see output indicating the server is running on `http://0.0.0.0:5000`.

## Connecting from App

- **Emulator:** The app should connect to `http://10.0.2.2:5000`.
- **Physical Device:** Ensure your phone and computer are on the **same Wi-Fi**.
  - Find your computer's local IP (e.g., `192.168.1.x`).
  - Update `lib/services/auth_service.dart` with this IP:

        ```dart
        static const String baseUrl = 'http://192.168.1.5:5000'; // Example
        ```
