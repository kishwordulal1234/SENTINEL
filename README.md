# SENTINEL
SENTINEL (SSH Enhanced Network Testing Intelligence &amp; Network Entry Logic)


# SENTINEL - Advanced SSH Security Assessment Framework
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)  
![Status](https://img.shields.io/badge/status-active-brightgreen)  
[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC%20BY--NC%20ND%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/)


[License](LICENSE)

Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License

This project is licensed under the CC BY-NC-ND 4.0. You are free to view the code, but you **CANNOT**:
- Copy, distribute, or modify the code.
- Use the code for commercial purposes.

For full details, see: https://creativecommons.org/licenses/by-nc-nd/4.0/

<p align="center">
  <img src="3.jpg" alt="SENTINEL Logo" width="600"/>
</p>

## 🔒 Overview

SENTINEL (SSH Enhanced Network Testing Intelligence & Network Entry Logic) is a sophisticated SSH security assessment framework designed for professional security researchers and system administrators. It combines advanced AI-driven credential generation with GPU acceleration capabilities to provide comprehensive SSH security testing.

## ✨ Key Features

- 🧠 **AI-Driven Credential Generation**: Utilizes advanced algorithms to generate intelligent username and password combinations
- 🚀 **GPU Acceleration**: Harnesses NVIDIA GPU power for enhanced performance
- 🛡️ **Stealth Mode**: Advanced evasion techniques to avoid detection
- 🔋 **Turbo Levels**: 4-tier performance optimization system
- 📊 **Real-time Analytics**: Live progress tracking and performance metrics
- 🔄 **Proxy Support**: Built-in proxy rotation capabilities
- 🎯 **Target Fingerprinting**: Automated system identification and version detection
- 💾 **Progress Persistence**: Automatic progress saving and resume capability

## 🚀 Performance Modes

SENTINEL offers four performance tiers:

| Turbo Level | Description | Use Case |
|-------------|-------------|-----------|
| Level 4 | Standard Mode | Basic assessment with balanced resource usage |
| Level 5 | Full Hardware | Optimized for multi-core systems |
| Level 6 | GPU Max | Maximum GPU utilization for high-speed operations |
| Level 7 | Extreme | Ultimate performance with mixed precision computing |

## 📋 Requirements

- Python 3.6 or higher
- NVIDIA GPU (Optional, for GPU acceleration)
- Required Python packages:
  ```
  paramiko>=2.7.2
  torch>=1.9.0
  numpy>=1.19.5
  tqdm>=4.61.0
  colorama>=0.4.4
  python-nmap>=0.7.1
  PySocks>=1.7.1
  ```

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/sentinel.git
   cd sentinel
   ```

2. Install required packages:
   ```bash
   pip install -r requirements-sentinel.txt
   ```

3. Optional: Install NVIDIA CUDA Toolkit for GPU acceleration

## 💻 Usage

Basic usage:
```bash
python setidevi.py --ip TARGET_IP --ai-mode
```

Advanced options:
```bash
python setidevi.py --ip TARGET_IP --port 22 --ai-mode --t 7 --max-attempts 5000
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| --ip | Target IP address (Required) |
| --port | SSH port (Default: 22) |
| --ai-mode | Enable AI credential generation |
| --t | Turbo level [4-7] |
| --max-attempts | Maximum number of attempts |
| --force-cpu | Force CPU mode |
| --threads | Number of concurrent workers |
| --proxy-list | Path to proxy list file |

## 🎯 Features in Detail

### AI Credential Generation
The tool employs advanced algorithms to generate contextually aware username and password combinations, significantly improving success rates compared to traditional wordlist approaches.

### GPU Acceleration
When running on NVIDIA GPUs, SENTINEL utilizes CUDA cores for:
- Parallel credential generation
- Batch processing optimization
- Mixed precision operations (Turbo Level 7)

### Stealth Capabilities
- Dynamic client fingerprint rotation
- Customizable connection timing
- Advanced evasion techniques
- Proxy support for enhanced anonymity

### Real-time Monitoring
- Progress percentage
- Current credentials being tested
- Success/failure status
- System resource utilization
- ETA and speed metrics

## 🔐 Security Considerations

SENTINEL is designed for authorized security testing only. Users must:
- Obtain proper authorization before testing
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Avoid unauthorized access attempts

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, and suggest features.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legal security assessment purposes only. Users are responsible for ensuring all usage complies with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this program.

## 🙏 Acknowledgments

- Special thanks to the PyTorch team for GPU acceleration capabilities
- The Paramiko project for SSH protocol implementation
- All contributors and security researchers who provided feedback

---
Created with ❤️ by unknone hart 
