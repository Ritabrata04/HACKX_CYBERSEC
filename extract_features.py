import re
import whois
import tldextract
import time
from urllib.parse import urlparse, parse_qs
import requests
import ipwhois
import socket

class ExtractFeatures:
    def parse_url(self, url):
        """
        Parses the given URL and extracts various components.

        This method takes in URL input and parses it.
        It extracts the domain, directories, files and parameters (if applicable) of the URL.
        It also counts the number of top-level domains in the URL.

        Args:
            url (str): The URL to be parsed.

        Returns:
            tuple: A tuple containing the extracted components of the URL.
                - domain (str): The domain name of the URL.
                - directories (str): The directories in the URL's path.
                - file (str): The file name in the URL's path.
                - parameters (dict): A dictionary of query parameters.
                - num_tlds (int): The number of top-level domains in the URL.
        """
        # Parse the URL into its components
        if '//' not in url:
            url = '//' + url

        parsed_url = urlparse(url)

        # Extract the domain name
        domain = parsed_url.netloc

        # Extract the path and split it into directories and file name
        path = parsed_url.path
        try:
            directories, file = path.rsplit('/', 1)
        except:
            if '.' in path:
                file = path
                directories = ""
            else:
                directories = path
                file = ""

        # Extract the query parameters
        parameters = parse_qs(parsed_url.query)

        tld_info = tldextract.extract(url)
        tld = tld_info.suffix

        # Count the number of top-level domains
        num_tlds = tld.count('.') + 1

        return domain, directories, file, parameters, num_tlds

    def get_domain_info(self, domain):
        """
        Retrieves information about a domain.

        This method takes in the domain of a URL as input, and fetches its information.
        It calculates the time elapsed since its creation and time remaining for its expiration.

        Args:
            domain (str): The domain to retrieve information for.

        Returns:
            tuple: A tuple containing the creation and expiration time of the domain in seconds.
                - creation_time_seconds (float): Time elapsed since domain creation in seconds.
                - expiration_time_seconds (float):  Time remaining for domain expiration in seconds.
        """
        try:
            # Get the domain information using python-whois
            domain_info = whois.whois(domain)

            # Extract the creation and expiration time
            creation_time = domain_info.creation_date
            expiration_time = domain_info.expiration_date

            # Convert the time to seconds
            if creation_time != None and expiration_time != None:
                creation_time_seconds = time.mktime(creation_time.timetuple())
                expiration_time_seconds = time.mktime(expiration_time.timetuple())
            else:
                raise ValueError
        except:
            creation_time_seconds = -1
            expiration_time_seconds = -1

        return creation_time_seconds, expiration_time_seconds
    
    def get_redirects(self, url):
        """
        Retrieves the number of redirects for a given URL.

        This method takes in a URL as input and assesses the number of times it redirects traffic.

        Args:
            url (str): The URL to retrieve redirects for.

        Returns:
            int: The number of redirects encountered.

        Note:
            The maximum number of redirects is limited to 20 to prevent infinite loops.
        """
        max_redirects = 20

        # Initialize the redirect count
        redirect_count = 0

        # Follow the redirects
        while True:
            response = requests.get(url, allow_redirects=False)
            if response.status_code == 301 or response.status_code == 302:
                url = response.headers['Location']
                redirect_count += 1
                if redirect_count >= max_redirects:
                    break
            else:
                break
        return redirect_count

    def get_features(self):
        """
        Retrieves a list of features used for URL analysis.

        This method returns the list of features that must be extracted from the URL to perform analysis.

        Returns:
            list: A list of features used for URL analysis.

        Note:
            The features include:
            - length_url: Length of the URL.
            - domain_length: Length of the domain name in the URL.
            - domain_in_ip: Whether the domain is represented as an IP address.
            - directory_length: Length of the directory path in the URL.
            - file_length: Length of the file name in the URL.
            - params_length: Length of the query parameters in the URL.
            - email_in_url: Whether an email address is present in the URL.
            - asn_ip: Autonomous System Number (ASN) associated with the IP address.
            - time_domain_activation: Time of domain activation.
            - time_domain_expiration: Time of domain expiration.
            - tls_ssl_certificate: Availability of TLS/SSL certificate.
            - qty_redirects: Number of redirects encountered.
            - qty_char_domain: Number of characters in the domain name.
        """
        features_list = ['length_url',
                            'domain_length',
                            'domain_in_ip',
                            'directory_length',
                            'file_length',
                            'params_length',
                            'email_in_url',
                            'asn_ip',
                            'time_domain_activation',
                            'time_domain_expiration',
                            'tls_ssl_certificate',
                            'qty_redirects',
                            'qty_char_domain']
        
        return features_list

    def url_to_features(self, url):
        """
        Extracts features from a given URL.

        This method takes in a URL as input and extracts all the relavant features for classification.
        Also, it rearranges the features according to the training dataset of the classfier.

        Args:
            url (str): The URL to extract features from.

        Returns:
            dict: A dictionary containing the extracted features.

        Note:
            The extracted features are the same the the ones specified in the documentation of get_features.

        See also:
            get_features(): Retrieves a list of features used for URL analysis.
            parse_url(): Parses the given URL and extracts its components.
            get_domain_info(): Retrieves information about a domain.
            get_redirects(): Retrieves the number of redirects for a given URL.
        """
        features_list = self.get_features()
        new_dataset = {}

        signs_dict = {"dot":".", 
                "hyphen":"-", 
                "underline": "_", 
                "slash":"/", 
                "questionmark": "?", 
                "equal":"=", 
                "at": "@", 
                "and": "&", 
                "exclamation": "!", 
                "space": " ", 
                "tilde": "~",
                "comma": ",", 
                "plus": "+", 
                "asterisk": "∗", 
                "hashtag": "#", 
                "dollar": "$", 
                "percent": "%"}

        return_val = self.parse_url(url)
        
        if  return_val != None:
            domain, directory, file, parameters, new_dataset['qty_tld_url'] = return_val
        else:
            return -1

        new_dataset['length_url'] = len(url)
        new_dataset['domain_length'] = len(domain)
        new_dataset['directory_length'] = len(directory) if directory != [""] else -1
        new_dataset['file_length'] = len(file) if file != [""] else -1
        new_dataset['params_length'] = len(str(parameters.values())) if parameters != {} else -1
        new_dataset['qty_params'] = len(parameters) if parameters != {} else -1
        new_dataset['time_domain_activation'], new_dataset['time_domain_expiration'] = self.get_domain_info(str(domain))
        
        # Check if IP is in domain
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is not None:
            new_dataset['domain_in_ip'] = int(True)
        else:
            new_dataset['domain_in_ip'] = int(False)
        
        # Check for tls certificate
        if url[:5] == 'https':
                new_dataset["tls_ssl_certificate"] = int(True)
        else:
                new_dataset["tls_ssl_certificate"] = int(False)

        # check for email in url
        if re.search(r'[\w\-.]+@[\w\-.]+\.\w+', url):
            new_dataset['email_in_url'] = int(True)
        else:
            new_dataset['email_in_url'] = int(False)

        ip_addresses = socket.getaddrinfo(domain, None)
        
        # Get the ASN of the IP address
        try:
            results = ipwhois.IPWhois.lookup_rdap(ip_addresses)      
            new_dataset['asn_ip'] = results['asn']
        except:
            new_dataset['asn_ip'] = -1

        try:
            new_dataset['qty_redirects'] = self.get_redirects(url)
        except:
            new_dataset['qty_redirects'] = -1

        new_dataset['qty_char_domain'] = 0
        
        for sign in signs_dict.values():
            new_dataset['qty_char_domain'] += domain.count(sign)

        reordered_dict = {k: new_dataset[k] for k in features_list}
        return reordered_dict
