import customtkinter as ctk
from tkinter import filedialog, messagebox
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket
import threading
import base64
import os


class FileServerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Home Server")
        self.geometry("800x600")
        self.resizable(True, True)  # Fixed window size

        # Set your custom icon here
        #self.iconbitmap("path/to/your/icon.ico")

        self.directory = ''
        self.username = ''
        self.password = ''
        self.port = 8000
        self.local_ip = self.get_local_ip()
        self.connected_devices = set()

        self.create_widgets()

    def create_widgets(self):
        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Directory to Share
        directory_frame = ctk.CTkFrame(frame)
        directory_frame.pack(anchor="w", pady=0)
        self.directory_label = ctk.CTkLabel(directory_frame, text="Directory to Share:")
        self.directory_label.pack(side="left", padx=5)
        self.directory_entry = ctk.CTkEntry(directory_frame, width=500)
        self.directory_entry.pack(side="left", padx=5)
        self.browse_button = ctk.CTkButton(directory_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side="left", padx=5)

        # Username
        self.username_label = ctk.CTkLabel(frame, text="Username:")
        self.username_label.pack(anchor="w", pady=0)
        self.username_entry = ctk.CTkEntry(frame, width=200)
        self.username_entry.pack(anchor="w", pady=0)

        # Password
        self.password_label = ctk.CTkLabel(frame, text="Password:")
        self.password_label.pack(anchor="w", pady=0)
        self.password_entry = ctk.CTkEntry(frame, show="*", width=200)
        self.password_entry.pack(anchor="w", pady=0)

        # Port
        self.port_label = ctk.CTkLabel(frame, text="Port:")
        self.port_label.pack(anchor="w", pady=0)
        self.port_entry = ctk.CTkEntry(frame, textvariable=ctk.StringVar(value=str(self.port)), width=100)
        self.port_entry.pack(anchor="w", pady=0)

        # On/Off switch for starting/stopping the server
        self.server_switch = ctk.CTkSwitch(frame, text="Server On/Off", command=self.toggle_server)
        self.server_switch.pack(anchor="w", pady=0)

        # Local Server Address
        self.local_ip_label = ctk.CTkLabel(frame, text=f"Default Server Address: http://{self.local_ip}:8000")
        self.local_ip_label.pack(anchor="w",pady=0)

        # Horizontal layout for connected devices and GET requests
        bottom_frame = ctk.CTkFrame(frame)
        bottom_frame.pack(fill="both", expand=True, pady=0)


        # Connected Devices
        connected_frame = ctk.CTkFrame(bottom_frame)
        connected_frame.pack(side="left", fill="both", expand=True, padx=5)
        self.connected_devices_label = ctk.CTkLabel(connected_frame, text="Connected Devices:")
        self.connected_devices_label.pack(anchor="w", pady=5)
        self.connected_devices_text = ctk.CTkTextbox(connected_frame, state="disabled", height=100)
        self.connected_devices_text.pack(fill="both", expand=True, pady=5)

        # GET Requests
        requests_frame = ctk.CTkFrame(bottom_frame)
        requests_frame.pack(side="left", fill="both", expand=True, padx=5)
        self.log_label = ctk.CTkLabel(requests_frame, text="GET Requests:")
        self.log_label.pack(anchor="w", pady=5)
        self.log_text = ctk.CTkTextbox(requests_frame, state="disabled", height=100)
        self.log_text.pack(fill="both", expand=True, pady=5)

        # user tip
        copyright_label = ctk.CTkLabel(frame, text="Tip: This program allows you to share a directory of files on your local network, with options for basic authentication, logging GET requests, and monitoring connected devices.", font=("Arial", 10), justify="left", wraplength=400)
        copyright_label.pack(pady=1)

        # Copyright info
        copyright_label = ctk.CTkLabel(frame, text="Copyright © Amir Faramarzpour 2024", font=("Arial", 10), justify="center", wraplength=400)
        copyright_label.pack(pady=0)



    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.insert(0, directory)

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.configure(state="disabled")

    def update_connected_devices(self, devices):
        self.connected_devices_text.configure(state="normal")
        self.connected_devices_text.delete("1.0", "end")
        for device in devices:
            self.connected_devices_text.insert("end", f"{device}\n")
        self.connected_devices_text.configure(state="disabled")

    def start_server(self):
        directory = self.directory_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        port = int(self.port_entry.get())
        if not directory or not username or not password or not port:
            messagebox.showerror("Error", "All fields are required!")
            return

        self.server_worker = ServerWorker(directory, username, password, port, self)
        self.server_worker.start()

        self.log(f"Server started on {self.local_ip}")
        self.server_switch.select()  # Update the switch state

    def stop_server(self):
        if self.server_worker:
            self.server_worker.stop_server()
            self.log("Server stopped")
            self.server_switch.deselect()  # Update the switch state

    def toggle_server(self):
        if self.server_switch.get() == 1:
            self.start_server()
        else:
            self.stop_server()

    def get_local_ip(self):
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = '127.0.0.1'
        return ip


class ServerWorker(threading.Thread):
    def __init__(self, directory, username, password, port, app):
        super().__init__()
        self.directory = directory
        self.username = username
        self.password = password
        self.port = port
        self.connected_devices = set()
        self.server = None
        self.app = app

    def run(self):
        handler_class = self.create_handler_class()
        self.server = HTTPServer(('', self.port), handler_class)
        self.server.directory = self.directory
        self.server.username = self.username
        self.server.password = self.password
        self.server.connected_devices = self.connected_devices
        self.server.app = self.app
        self.app.log(f"Serving on port {self.port}...")
        self.server.serve_forever()

    def create_handler_class(self):
        parent = self
        class CustomHandler(AuthHTTPRequestHandler):
            def log_message(self, format, *args):
                parent.app.log(format % args)

            def do_GET(self):
                if self.headers.get('Authorization') is None:
                    self.do_AUTHHEAD()
                    self.wfile.write(b'Unauthorized access')
                else:
                    auth_type, credentials = self.headers['Authorization'].split(' ', 1)
                    if auth_type == 'Basic':
                        username, password = base64.b64decode(credentials).decode().split(':', 1)
                        if username == self.server.username and password == self.server.password:
                            os.chdir(self.server.directory)
                            self.server.connected_devices.add(self.client_address[0])
                            parent.app.update_connected_devices(self.server.connected_devices)
                            return super().do_GET()
                    self.do_AUTHHEAD()
                    self.wfile.write(b'Unauthorized access')
        return CustomHandler

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.app.log("Server stopped.")


class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Login Required"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Unauthorized access')

    def do_GET(self):
        if self.headers.get('Authorization') is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')
        else:
            auth_type, credentials = self.headers['Authorization'].split(' ', 1)
            if auth_type == 'Basic':
                username, password = base64.b64decode(credentials).decode().split(':', 1)
                if username == self.server.username and password == self.server.password:
                    os.chdir(self.server.directory)
                    self.server.connected_devices.add(self.client_address[0])
                    self.server.app.update_connected_devices(self.server.connected_devices)
                    self.server.app.log(f"Request from {self.client_address[0]}")
                    return super().do_GET()
            self.do_AUTHHEAD()
            self.wfile.write(b'Unauthorized access')


if __name__ == "__main__":
    app = FileServerApp()
    app.mainloop()
