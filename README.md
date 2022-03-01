# SUNBURST
Detection for SUNBURST C2 Stage-1 using Shannon Entropy

	About:
		Using Shannon Entropy to detect Domain-Generation Algorithms (DGA).
		It should only be fed FQDNs into the function or read from a CSV file.
			SYNTAX: Prefix_or_subdomain.Domain.TLD
		Made due to APTs leveraging long-string DGA for Kill Chain: C2.
		ID long string URLs that have high entropy > 2x Standard Deviations.
		Looking at upperbound 2.5% of URLs with long prefixes/subdomains.
		Saving extra metadata if CND analysts need it (ie. Prefix Length)
    
	Requirements:
		1) Python 3.9+
		2) Python exists in PATH variable
		3) All imports listed (pip install, if necessary)
		4) Input DNS log has 1x FQDN per line (no other punctuation)
		5) Cisco Top-1M (CSV, ZIP) or Majestic (CSV) Top-1M exist in same folder as the script.
    
	How-to-Run (INTERACTIVE MODE is ON, see VARIABLES):
		1) Install Python 3.9.x
		2) Stage all input files with correct formatting (domains in a text file, 1 per line, no punctuation)
		3) Ensure input files are in the same directory/folder as this script.
		4a) (Windows) Open this script in Python IDLE or Visual Studio Code.
		4b) (Linux) $~: python3 shannon.py
		5) Enter the input DNS log file to examine.
		6) Enter the Cisco Umbrella (CSV/ZIP) or Majestic Top-1M file (CSV) to leverage.
		7) Wait for the Frequency and Shannon Entropy values to generate.
		8) Examine the output files.
    
	How-to-Run (INTERACTIVE MODE is OFF, see VARIABLES):
		1) Install Python 3.9.x
		2) Stage all input files with correct formatting (domains in a text file, 1 per line, no punctuation)
		3) Ensure input files are in the same directory/folder as this script.
		4a) (Windows) Open this script in Python IDLE or Visual Studio Code.
		4b) (Linux) $~: python3 shannon.py
		5) Input Log to analyze is "domains.txt", see VARIABLES.
		6) Pick Top-N file to build dictionary probability, see VARIABLES.
		7) Wait for the Frequency and Shannon Entropy values to generate.
		8) Examine the output files.
    
	Assumptions:
		1) Capital and lowercase letters have equal probability of appearance.
			a) Neglecting that TOR nodes alter case-sensitivity in DNS queries & 0x20-encoding.
		2) ETOAN character frequency chart is insufficient due to missing: 0-9, "-", and "_"
			a) Domains can have hyphens (-) and underscore (_) and numbers.
		3) Not designed to counter ExploderBot DGA.
		4) Input: simple text file, each URL is on its own row - nothing else.
		5) Input is composed of strictly URL strings w/o prohibited chars.
		6) Input and output files must be in the same folder as this script.
		7) Python3 is in PATH variable.
    
	Data Set (Domains):
		Data set used was derived from Pi-Hole query log (12 hr window) extracted from SQLite.
		
		# BASH:
		$~: sqlite3 /etc/pihole/pihole-FTL.db \
			"SELECT domain FROM queries WHERE \
			timestamp >='$(($(date +%s) - 43200))'" > domains.txt
		
		Data was deduped using Excel > Data > Remove Duplicates
		Data for Reverse Lookups (PTR) in-addr.arpa were also removed.
    
	Data Set (Probabilities):
		Leveraging RedCanary's results for DGA analysis, this script takes URL and calculates the shannon entropy.
      
	DevOps Testing Phase Line:
		1) shannon.py (1.0) - Get calculations to work with static RedCanary Dictionary.
		2) shannon.py (1.1) - Minor testing merged into 1.0.
		3) dictionary.py (1.0) - Test opening/closing Cisco + Majestic Top-1M.
		4) shannon.py (2.0) - Combining 1.0 w/ dictionary.py tested functions.
    
	Reference:
		# Splunk Shannon Entropy - where the idea came from*
		https://www.splunk.com/en_us/blog/tips-and-tricks/when-entropy-meets-shannon.html
    
		# SANS Mark Baggett - Tool RedCanary used to analyze Alexa Top 1M
		https://github.com/markbaggett/freq
    
		# RedCanary - Blog where Probability scores come from
		# https://redcanary.com/blog/threat-hunting-entropy/
    
		# Alexa's Top 1M Domains - Data Corpus used by RedCanary
		https://www.alexa.com/topsites
    
		# DGA Detector
		https://github.com/exp0se/dga_detector
    
		# Shannon Entropy - Formula
		https://towardsdatascience.com/the-intuition-behind-shannons-entropy-e74820fe9800
