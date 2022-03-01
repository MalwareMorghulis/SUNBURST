#/bin/python3

'''
	Title: shannon.py
	Author: Adam D. Wong (@MalwareMorghulis)
	Class: DSU INFA 723 Cryptography (Spring 2021 Project)
	Python: v3.9.0
	Version Control: 2.1 (20 MAY 2021)
	Type: PRODUCTION
	Tested: Windows 10 w/ Visual Studio Code

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
		2) Stage all input files with correct formatting
			(domains in a text file, 1 per line, no punctuation)
		3) Ensure input files are in the same directory/folder as this script.
		4a) (Windows) Open this script in Python IDLE or Visual Studio Code.
		4b) (Linux) $~: python3 shannon.py
		5) Enter the input DNS log file to examine.
		6) Enter the Cisco Umbrella (CSV/ZIP) or Majestic Top-1M file (CSV) to leverage.
		7) Wait for the Frequency and Shannon Entropy values to generate.
		8) Examine the output files.

	How-to-Run (INTERACTIVE MODE is OFF, see VARIABLES):
		1) Install Python 3.9.x
		2) Stage all input files with correct formatting
			(domains in a text file, 1 per line, no punctuation)
		3) Ensure input files are in the same directory/folder as this script.
		4a) (Windows) Open this script in Python IDLE or Visual Studio Code.
		4b) (Linux) $~: python3 shannon.py
		5) Input Log to analyze is "domains.txt", see VARIABLES.
		6) Pick Top-N file to build dictionary probability, see VARIABLES.
		7) Wait for the Frequency and Shannon Entropy values to generate.
		8) Examine the output files.

	Assumptions:
		1) Capital and lowercase letters have equal probability of appearance.
			a) Neglecting that TOR nodes alter case-sensitivity 
				in DNS queries & 0x20-encoding.
		2) ETOAN character frequency chart is insufficient due to missing:
			0-9, "-", and "_"
			a) Domains can have hyphens (-) and underscore (_) and numbers.
		3) Not designed to counter ExploderBot DGA.
		4) Input: simple text file, each URL is on its own row - nothing else.
		5) Input is composed of strictly URL strings w/o prohibited chars.
		6) Input and output files must be in the same folder as this script.
		7) Python3 is in PATH variable.

	Data Set (Domains):
		Data set used was derived from home Pi-Hole query log (12 hr window)
		extracted from SQLite
		
		# BASH:
		$~: sqlite3 /etc/pihole/pihole-FTL.db \
			"SELECT domain FROM queries WHERE \
			timestamp >='$(($(date +%s) - 43200))'" > domains.txt
		
		Data was deduped using Excel > Data > Remove Duplicates

		Data for Reverse Lookups (PTR) in-addr.arpa were also removed.

	Data Set (Probabilities):
		Leveraging RedCanary's results for DGA analysis, this script takes URL
			and calculates the shannon entropy.

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

'''

### IMPORTS ###
import csv
import math
import os
import statistics
import sys
import time
import zipfile

# SHANNON ENTROPY FORMULA
# H(x) = sum( P(xn) * log2(1/P(xn)) ) where n = {1:i}

### VARIABLES ###
# INTERACTIVE MODE T = user input, F = staticly set file
interactive_mode = False

# TOP-N Mode
# 0 = Cisco Umbrella (ZIP File)
# 1 = Cisco Umbrella (CSV File)
# 2 = Majestic Million (CSV File)
# <OTHER> = program will default to using RedCanary. Add other files as necessary
TopN_mode = 0

# Filenames for long-term preservation.
input_log = 'domains.txt'
output_filename = 'OUTPUT_all_analyzed_domains.csv'
suspect_filename = 'OUTPUT_suspected_DGA_watchlist.csv'

# Top-1M Files
cisco_zipped = 'top-1m.csv.zip'
cisco_1M = 'top-1m.csv'
majestic_1M = 'majestic_million.csv'

# Empty Dictionary for Custom Top-N Files
domain_char_freq_dict = {}

# Creating empty lists for organization or sorting.
calculated = []
domain_tuples = []

# Creating empty sets for statistical analysis.
all_url_lengths = set()
all_entropies = set()
all_prefixes = set()

# Initializing variables for statistical analysis.
avg_url_length = 0
sd_url_length = 0
avg_entropy = 0
sd_entropy = 0


### FUNCTIONS for Testing ###
def test_dict():
	""" Test RedCanary's calculations to ensure sum(probabilities) = 1 """
	test_sum = 0
	# For each character (key) in the dictionary, sum(frequency probability).
	for key in domain_char_freq_dict:
		test_sum += domain_char_freq_dict[key]

	# Print sum of the probability - it should be 1 (or 100%).
	print(test_sum)
	return None

def iterate(this_url):
	"""	Testing reading a URL without considering '.' """
	for this_char in this_url:
		if '.' in this_char:
			pass
		else:
			print(char)

def useRedCanary():
	""" Use RedCanary's static character frequency table """
	# RedCanary's relative entropy per char derived from Alexa 1M dataset.
	redCanary_dict = {
		"-": 0.013342298553905901,
		"_": 0.00000904562613824129,
		"0": 0.0024875471880163543,
		"1": 0.004884638114650296,
		"2": 0.004373560237839663,
		"3": 0.0021136613076357144,
		"4": 0.001625197496170685,
		"5": 0.0013070929769758662,
		"6": 0.0014880054997406921,
		"7": 0.001471421851820583,
		"8": 0.0012663876593537805,
		"9": 0.0010327089841158806,
		"a": 0.07333590631143488,
		"b": 0.04293204925644953,
		"c": 0.027385633133525503,
		"d": 0.02769469202658208,
		"e": 0.07086192756262588,
		"f": 0.01249653250998034,
		"g": 0.038516276096631406,
		"h": 0.024017645001386995,
		"i": 0.060447396668797414,
		"j": 0.007082725266242929,
		"k": 0.01659570875496002,
		"l": 0.05815885325582237,
		"m": 0.033884915513851865,
		"n": 0.04753175014774523,
		"o": 0.09413783122067709,
		"p": 0.042555148167356144,
		"q": 0.0017231917793349655,
		"r": 0.06460084667060655,
		"s": 0.07214640647425614,
		"t": 0.06447722311338391,
		"u": 0.034792493336388744,
		"v": 0.011637198026847418,
		"w": 0.013318176884203925,
		"x": 0.003170491961453572,
		"y": 0.016381628936354975,
		"z": 0.004715786426736459
	}
	return redCanary_dict

### FUNCTIONS for Shannon Entropy Calculation ###
def find_entropy(domain, freq_dict):
	"""	Calculate Shannon Entropy based on URL & RedCanary Probabilities """
	# Removing possible whitespace on rightside of URL.
	url = domain.rstrip()

	# Carve out the subdomain prefix only for calculation.
	subdomain_prefix = url.split(".")[0]
	#print(subdomain_prefix)
	
	# Resetting entropy per URL.
	this_entropy = 0

	# Iterate through each character of the URL.
	for char in subdomain_prefix:
		if '.' in char:
			pass
		else:
			# Calculating entropy Log2 (because using binary values).
			p = freq_dict[char]
			this_entropy += p * math.log2(1/p)

	# Add the URL length to a set for statistical analysis.
	all_url_lengths.add(len(url))

	# Add the entropy to a set for statistical analysis.
	all_entropies.add(this_entropy)

	# Return FLOAT
	return this_entropy

def prefix(full_domain_name):
	""" Calculate the 1st prefix length (string before 1st dot """
	# Disregard the '.' and grab the first prefix or subdomain of the URL.
	prefix_size = len(full_domain_name.split('.')[0])
	
	# Add the prefix size to a set for statistical analysis
	all_prefixes.add(prefix_size)

	# Return INT
	return prefix_size

def url_len(url):
	"""	Counting URL without considering '.' """
	# Total count for characters in URL w/o '.' char.
	count = 0
	for char in url:
		if '.' in char:
			pass
		else:
			count += 1

	# Return INT
	return count

def sort_list(this_list):
	""" Lamda Function sorts pairs in list by 2nd-part (Shannon Entropy). """
	# Sort the domain tuples (Entropy, FQDN) pairs high entropy items.
	# Return SORTED LIST
	return sorted(this_list, key = lambda pairs: pairs[0])

def run_stats(this_set):
	"""	Find standard deviation and mean (average) for the data set. """
	# Simply calculate Mean & StdDev for this set.
	# Return TUPLE of FLOATS
	return statistics.mean(this_set), statistics.stdev(this_set)

def run_analysis():
	""" Calculate stats for URL, Shannon Entropy, and Prefixes. """
	# Calculate Mean & StdDev for the 3x Sets: URL Length, Entropy, Prefix.
	url_len_stats = run_stats(all_url_lengths)
	shannon_stats = run_stats(all_entropies)
	pref_stats = run_stats(all_prefixes)

	# Return TRIPLE of TUPLES(FLOAT, FLOAT)
	return url_len_stats, shannon_stats, pref_stats

def find_evil(this_list, stats_tuple):
	""" Find FQDNs with Shannon Entropy higher than 2x Std_Dev from Mean. """
	# Break the tuple apart for use.
	avg, std_dev = stats_tuple

	# Consider 2+ Standard Deviations to be statistically-significant.
	suspect = avg + (2 * std_dev)

	# Prepare the "Suspect" output file.
	with open(suspect_filename, 'w', newline = '') as sus_csv:
		sus_writer = csv.writer(sus_csv, delimiter = ',')
		sus_writer.writerow(["Shannon_Entropy", "Suspect_FQDN"])

		print("### Suspicious DGA - Detections Listed ###")

		# Iterate through the sorted and paired list of FQDNs and Entropies.
		for pairing in this_list:
			# Compare Entropy or column [0] and compare against stats marker.
			if pairing[0] < suspect:
				pass
			else:
				# Send suspected DGAs to Standard_Out
				print("Shannon_Entropy: %.16f; Suspect_FQDN: %s" % pairing)
				shannon_entropy, sus_fqdn = pairing
				sus_writer.writerow([shannon_entropy, sus_fqdn])

	# Close the Watchlist CSV.
	sus_csv.close()

	print()
	print("### Entropy Test ###")
	print("Shannon_Entropy > %.16f is statistically significant!" % suspect)

	# Return NULL
	return None

def testInputLog(log_file):
	""" Test the user input for issues in the DNS query logs """

	# if the path is a file
	if os.path.isfile(log_file):
		pass
	else:
		print("WARNING: Bad Input - Use a DNS (text) log file which has one domain per row without any other data or punctuation.")
		print("Exiting...")
		sys.exit(0)

	# Return NULL
	return None

def countLetter(wordlist):
	""" Take a list of words and count the characters """

	# Staging an empty dictionary to contain character counts.
	counter_dict = {}

	# Count the characters in each word of the master list.
	for word in wordlist:
		for character in word:
			# Determine if the character exists in the dictionary.
			if character in counter_dict:
				# Increment the count for this character.
				counter_dict[character] += 1
			else:
				# This is a new character.
				counter_dict[character] = 1

	# Account for underscore ("_") - illegal char in DNS, but sometimes used.
	if "_" in counter_dict:
		pass
	else:
		counter_dict["_"] = 0

	return counter_dict

def calculateFreq(counted_char_dict):
	""" Calculate Probability (w/ replacement) based on Frequency of Characters """

	# Temporary dictionary to hold probability values.
	probability_dict = {}

	# Counting the total number of characters.
	totalChars = sum(counted_char_dict.values())

	# For each Key-Value pair in the character count dictionary, calculate probability.
	for key, value in counted_char_dict.items():
		# Calculating probability with replacement on each character.
		probability_dict[key] = value / totalChars

	# Cannot divide Log(1/0) in Shannon Entropy, set low value for underscore ("_")
	if probability_dict["_"] == 0:
		probability_dict["_"] = 1e-100

	return probability_dict

def useCisco(cisco_input):
	""" Using the Cisco Top-1M file """
	# Open the extracted Cisco Top-1M file.
	extracted = open(cisco_input, 'r')
	all_extracted_rows = extracted.readlines()
	extracted.close()

	# Temporary list to hold word set for dictionary building
	cisco_domain_corpus = []
	cisco_counted_chars = {}

	# Expected Cisco CSV contains headers: "Rank, FQDN"
	print("Building data corpus for character frequency dictionary...")
	print("Standby!")

	# Iterate through each row of the extracted Cisco CSV
	for extracted_row in all_extracted_rows:
			
		# Row will come out as "rank,fqdn" (ie: "1,google.com")
		# Grab 2nd item (i=1) in tuple: FQDN by splitting the string on ","
		extracted_fqdn = extracted_row.split(",")[1]
		split_extracted_fqdn = extracted_fqdn.split(".")

		# Remove the TLD from each FQDN
		cisco_domain_corpus += split_extracted_fqdn[:-1]

	print("Data corpus constructed.")
	print()
	print("Calculating character frequency...")
			
	# Build the probability dictionary based on the char count dictionary
	cisco_counted_chars = countLetter(cisco_domain_corpus)
	cisco_temp_dict = calculateFreq(cisco_counted_chars)
	print("ANALYZED - Character Probability (w/ Replacement).")
	time.sleep(3)
	print()

	return cisco_temp_dict

def useMajestic(majestic_input):
	""" Using the Majestic Top-1M file """
	# Open the Majestic Top-1M file.
	# Set encoding to UTF-8 for UnicodeDecodeError
	majestic = open(majestic_input, 'r', encoding = "utf-8")
	all_majestic_rows = majestic.readlines()
	majestic.close()
	
	# Temporary list to hold word set for dictionary building
	majestic_domain_corpus = []
	majestic_counted_chars = {}

	# Expected Majestic CSV contains headers: "GlobalRank,TldRank,FQDN,TLD, [...]"
	print("Building data corpus for character frequency dictionary...")
	print("Standby!")

	cleaned_majestic_lines = all_majestic_rows[1:]

	# Iterate through each row of the Majestic CSV (w/o header)
	for majestic_row in cleaned_majestic_lines:
			
		# Row will come out as:
		# "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs"
		# Grab 3rd item (i=2) in tuple: FQDN by splitting the string on ","
		majestic_fqdn = majestic_row.split(",")[2]
		split_majestic_fqdn = majestic_fqdn.split(".")

		# Remove the TLD from each FQDN
		majestic_domain_corpus += split_majestic_fqdn[:-1]

	print("Data corpus constructed.")
	print("Calculating character frequency...")
			
	# Build the probability dictionary based on the char count dictionary
	majestic_counted_chars = countLetter(majestic_domain_corpus)
	majestic_temp_dict = calculateFreq(majestic_counted_chars)
	print("Character Probability (w/o Replacement) - analysis complete!")
	print()

	return majestic_temp_dict

def makeDictionary(domains_file):
	""" Build the Character Frequency from the Top-N Sample """

	# Access the global marker for which probability table is being used.
	global stats_in_use

	# Temporary dictionary to hold probabliity values.
	generated_dict = {}

	# Check if the Top-N file exists
	if os.path.isfile(domains_file):

		# Check if the Top-N file is a ZIP
		if zipfile.is_zipfile(domains_file):

			# Extract the file from the Cisco Top-1M ZIP
			with zipfile.ZipFile(domains_file) as this_zip:
				this_zip.extract(cisco_1M)
				this_zip.close()

			generated_dict = useCisco(cisco_1M)
			print("Utilizing Cisco (zipped) Top-1M probability table...")
			print()
			
			# If using the extracted CSV from ZIP, cleanup afterwards.
			print("Initiating cleanup... removing " + cisco_1M + "... DONE.")
			if os.path.exists(cisco_1M):
				os.remove(cisco_1M)
			
			# Status Variable
			stats_in_use = "Cisco Top-1M (ZIP File)"

		# Otherwise the Top-N file should be a CSV file.
		else:
			# Use Cisco Top-1M (flatfile, non-ZIP version)
			if cisco_1M in domains_file:
				# Cisco Top-1M File is already extracted by the User
				generated_dict = useCisco(cisco_1M)
				print("Utilizing Cisco (Flat File) Top-1M probability table...")
				print()
				stats_in_use = "Cisco Top-1M (Flat File)"
			
			# Use Majestic Top-1M
			elif majestic_1M in domains_file:
				generated_dict = useMajestic(majestic_1M)
				print("Utilizing Majestic (Flat File) Top-1M probability table...")
				print()
				stats_in_use = "Majestic Top-1M (Flat File)"

			# Default to RedCanary	
			else:
				print()
				print("###################################################################################")
				print("# WARNING: Unknown Top-N file used - defaulting to RedCanary's probability table. #")
				print("###################################################################################")
				print()
				print()
				generated_dict = useRedCanary()
				stats_in_use = "RedCanary (Static Vendor Data)"

	# User's input file does not exist - use RedCanary
	else:
		print("##########################################################################")
		print("# WARNING: File Not Found - defaulting to RedCanary's probability table. #")
		print("##########################################################################")
		generated_dict = useRedCanary()
		stats_in_use = "RedCanary (Static Vendor Data)"

	return generated_dict

def main():
	""" Main function to define execution of the tool """

	# Read Input from User
	print()
	print()
	print("Shannon Entropy DGA Detection Tool v2.0")
	print()

	# Interactive Mode Settings
	# Set in VARIABLES Section
	if interactive_mode is True:
		input_DNS_filename = input("Enter DNS log file to analyze: ")
		input_1M_filename = input("Enter Top-1M Websites File to build the Shannon Entropy Table: ")
	else:
		input_DNS_filename = input_log

		# Set in VARIABLES Section
		if TopN_mode == 0:
			input_1M_filename = cisco_zipped
		elif TopN_mode == 1:
			input_1M_filename = cisco_1M
		elif TopN_mode == 2:
			input_1M_filename = majestic_1M
		else:
			# RedCanary Table will be used in makeDictionary()
			input_1M_filename = ""

	print()

	# Testing the input files
	testInputLog(input_DNS_filename)

	# makeDictionary() already tests the char data set input.
	# Select the Probability Dictionary based on the User Input.
	domain_char_freq_dict = makeDictionary(input_1M_filename)

	# Ingest the converted exported (input file) from Pi-Hole Logs
	ingest_file = open(input_DNS_filename, 'r')
	all_queries = ingest_file.readlines()
	ingest_file.close()

	# Open the Output CSV.
	# Set filename, open write mode, newline = '' prevents extra empty rows.
	with open(output_filename, 'w', newline = '') as master_outcsv:

		# Setup the writer to send text to the newly open CSV.
		out_writer = csv.writer(master_outcsv, delimiter = ',')

		# Write Header to output CSV.
		out_writer.writerow(["Shannon_Entropy", "FQDN", "Prefix", "TotalChar"])

		# For each URL execute the entropy calculations.
		for fqdn in all_queries:

			# Staging data
			pref = prefix(fqdn)
			entropy = find_entropy(fqdn, domain_char_freq_dict)
			char_count = url_len(fqdn)
			this_fqdn = fqdn.rstrip()

			# TESTING - Printout and String Formatting.
			# print("Entropy is: %.16f; FQDN is: %s; Prefix is: %i; Total_Char is: %i" % (entropy, this_fqdn, pref, char_count))

			# Save this row of data for the master output file.
			calculated = [entropy, this_fqdn, pref, char_count]

			# Create a tuple (FQDN, Entropy) for sorting & stats-comparison.
			pair = entropy, this_fqdn

			# Save the specific tuple.
			domain_tuples.append(pair)

			# Send row data to Master Output CSV.
			out_writer.writerow(calculated)

	# Closing the Master Output File.
	master_outcsv.close()

	# Pull Stats Tuples - a: URL Length, b: Entropy, c: Prefix Length
	url_stat_pair, entropy_stat_pair, pref_stat_pair = run_analysis()

	# Sort list of Domain Tuples or Pairs: FQDN, Entropy
	sorted_entropies = sort_list(domain_tuples)

	# Print out metadata used in the Shannon Entropy analysis.
	print()
	print("Generating OUTPUT... wait for 'COMPLETE'")
	print()
	time.sleep(7)
	print("######## OUTPUT ########")
	print()
	print("### Character Probabilities ###")
	print("Values derived from: " + stats_in_use)
	print()
	time.sleep(3)
	print("Probability Set: " + str(domain_char_freq_dict))
	time.sleep(3)
	print()

	# Compare w/ Mean
	find_evil(sorted_entropies, entropy_stat_pair)
	time.sleep(3)

	# Print high-level summary used to analyze domains.
	print()
	print("### ENTROPY ###")
	print("Avg Entropy is: %f, StdDev is: %f" % entropy_stat_pair)
	print()
	print("# Other Metadata #")
	print("Avg Prefix Length is: %f, StdDev is: %f" % pref_stat_pair)
	print("Avg URL Length is: %f, StdDev is: %f" % url_stat_pair)
	print()
	print("COMPLETE - see saved output files.")


### MAIN ###
if __name__ == "__main__":
    main()

### TEST OPERATIONS ###
# iterate("google.com")
# find_entropy("www.google.com", domain_char_freq_dict)
