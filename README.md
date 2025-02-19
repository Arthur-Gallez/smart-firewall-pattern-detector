# Smart Firewall Pattern Detector
## Installation
1. Clone the repository
```bash
git clone https://github.com/Arthur-Gallez/smart-firewall-pattern-detector.git
```
2. Install the dependencies
```bash
cd smart-firewall-pattern-detector
```
You may want to create a virtual environment before installing the dependencies.
```bash
python3 -m venv .venv
source .venv/bin/activate
```
Then install the dependencies.
```bash
pip install -r requirements.txt
```

## Usage
The **Smart Firewall Pattern Detector** can be used with a command line interface or with a web interface.

### Web interface
```bash
python3 main.py --web
```
Then open your browser and go to `http://127.0.0.1:5000`, or simply click on the link displayed in the terminal.

### Command line interface
```bash
python3 main.py --file <file>
```
Where `<file>` is the path to the pcap file you want to analyze.

For more information, and more advanced usage, you can use the `--help` option.
```bash
python3 main.py --help
```