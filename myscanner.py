import argparse
import sys
import re
import json

from urllib.parse import urlparse
from packaging import version
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# os.environ['NO_PROXY'] = '127.0.0.1'
proxies = {
}


custom_headers = {
    "Accept-Encoding": "identity",
    "Connection": "Keep-Alive",
    "Accept": "*/*"

}

# set of core components
core_components = {
    "com_admin", "com_ajax", "com_associations", "com_banners", "com_cache", 
    "com_categories", "com_checkin", "com_config", "com_contact", "com_content", 
    "com_contenthistory", "com_cpanel", "com_csp", "com_fields", "com_finder", 
    "com_installer", "com_joomlaupdate", "com_languages", "com_login", "com_mailto", 
    "com_media", "com_menus", "com_messages", "com_modules", "com_newsfeeds", 
    "com_plugins", "com_postinstall", "com_redirect", "com_search", "com_tags", 
    "com_templates", "com_users", "com_workflow", "com_wrapper"
}

core_modules = {
    "mod_languages", "mod_menu"
}


timeoutconnection = 15

def print_scanner_results_with_extensions(scanner_output, extensions_file):
    # Load extensions.json
    with open(extensions_file, 'r') as f:
        extensions = json.load(f)

    with open("extensions-ignore.json", 'r') as f:
        extensions_ignore = json.load(f)

    # Print components
    if 'components' in scanner_output:
        for component_key, component_entries in scanner_output['components'].items():         
            if component_entries:
                site_component_name = component_entries[0]['name']
                site_component_urls = component_entries[0]['urls']
                site_component_version = ''

                raw_site_component_version = component_entries[0]['version']
                if ' ' in raw_site_component_version:
                    parts = raw_site_component_version.split()
                    for part in parts:
                        try:
                            site_component_version = version.parse(part)
                            break  # Exit loop once a valid version is found
                        except version.InvalidVersion:
                            continue
                    else:
                        # No valid version found
                        raise ValueError(f"No valid version found in '{raw_site_component_version}'")
                else:
                    # No space: assume it's a clean version string
                    site_component_version = version.parse(raw_site_component_version)            

                for ext in extensions:
                    try:
                        ext_name = ext['extension_name']

                        if component_key[4:] in extensions_ignore['components'].keys():
                            if ext_name in extensions_ignore['components'][component_key[4:]]:
                                continue
                        if ext_name in extensions_ignore['full-extensions']:
                            continue

                        ext_version = ext['other']['ext_page_data']['data']['Version']
                        ext_update = " ".join(ext['other']['ext_page_data']['data']['Last updated'].split()[:3])
                        if ext_name.lower() == component_entries[0]['name'].lower() or component_key[4:].lower() in ext_name.lower():
                            if site_component_version < version.parse(ext_version):
                                output = {}
                                data = {}
                                data['identified_version'] = site_component_version
                                data['matched_extension_name'] = ext_name
                                data['matched_extension_version'] = ext_version
                                data['matched_extension_last_update'] = ext_update
                                data['matched_by'] = component_key
                                data['urls'] = site_component_urls

                                output[site_component_name] = data
                                print(output)

                    except KeyError:
                        print(f"Error: {ext['extension_name']} does not have version in extensions.json")

    # Print modules
    if 'modules' in scanner_output:
        for module_key, module_entries in scanner_output['modules'].items():
            if module_entries:
                site_module_name = module_entries[0]['name']
                site_module_urls = module_entries[0]['urls']
                site_module_version = ''

                raw_site_module_version = module_entries[0]['version']
                if ' ' in raw_site_module_version:
                    parts = raw_site_module_version.split()
                    for part in parts:
                        try:
                            site_module_version = version.parse(part)
                            break  # Exit loop once a valid version is found
                        except version.InvalidVersion:
                            continue
                    else:
                        # No valid version found
                        raise ValueError(f"No valid version found in '{raw_site_module_version}'")
                else:
                    # No space: assume it's a clean version string
                    site_module_version = version.parse(raw_site_module_version)
                
                for ext in extensions:
                    try:
                        ext_name = ext['extension_name']

                        if module_key[4:] in extensions_ignore['modules'].keys():
                            if ext_name in extensions_ignore['modules'][module_key[4:]]:
                                continue
                        if ext_name in extensions_ignore['full-extensions']:
                            continue

                        ext_version = ext['other']['ext_page_data']['data']['Version']
                        ext_update = " ".join(ext['other']['ext_page_data']['data']['Last updated'].split()[:3])
                        if ext_name.lower() == module_entries[0]['name'].lower() or module_key[4:].lower() in ext_name.lower():
                            if site_module_version < version.parse(ext_version):

                                output = {}
                                data = {}
                                data['identified_version'] = site_module_version
                                data['matched_extension_name'] = ext_name
                                data['matched_extension_version'] = ext_version
                                data['matched_extension_last_update'] = ext_update
                                data['matched_by'] = module_key
                                data['urls'] = site_module_urls

                                output[site_module_name] = data
                                print(output)
                    except KeyError:
                        print(f"Error: {ext['extension_name']} does not have version in extensions.json")

    if 'plugins' in scanner_output:
        pass


def blob_ext_identification(conn, final_urls, user_agent):

    if conn.request.url[-1] == '/':
        main_url = conn.request.url[:-1]
    else:
        main_url = conn.request.url

    redirects_list = [item for item in final_urls if item != main_url]
    site_blobs = [conn.text]

    for url in redirects_list:
        request_headers = {**custom_headers, "User-Agent": user_agent}
        conn = requests.get(url, headers=request_headers, timeout=timeoutconnection, proxies=proxies, verify=False)
        site_blobs.append(conn.text)

    index_components = []
    index_modules = []
    index_plugins = []
    index_packages = []
    index_templates = []

    for blob in site_blobs:
        index_components.extend(re.findall(r'com_\w+', blob))
        index_modules.extend(re.findall(r'mod_\w+', blob))
        index_plugins.extend(re.findall(r'plg_\w+|\w+_plg+', blob))
        index_packages.extend(re.findall(r'pkg_\w+|\w+_pkg', blob))
        index_templates.extend(re.findall(r"/templates/([\w-]+)", blob))


    index_components = list(set(index_components) - core_components)
    index_modules = list(set(index_modules) - core_modules)
    index_plugins = list(set(index_plugins))
    index_packages = list(set(index_packages))
    index_templates = list(set(index_templates))

    return index_components, index_modules, index_packages, index_plugins, index_templates


# com_name contains "com_" prefix
def check_for_component(url, com_name, user_agent):

    ## for now it is list because of multiple URL types for same module
    final_out = []

    paths = [
        "/administrator/components/" + com_name + "/manifest.xml",
        "/administrator/components/" + com_name + "/" + com_name[4:] + ".xml",
        "/administrator/components/" + com_name + "/" + com_name + ".xml"
    ]

    for path in paths:

        try:
            request_headers = {**custom_headers, "User-Agent": user_agent}
            conn = requests.get(url + path, headers = request_headers, timeout=timeoutconnection, proxies=proxies, verify=False)

            ## Is verifying 200 and content type sufficient ?
            if conn.status_code == 200:
                if "xml" in conn.headers.get("Content-Type", "").lower():

                    ## There are multiple lines with version in the .xml files..
                    ## Some extensions have multuple plg,com,mod with different versions
                    versions = re.findall(r"<version[^>]*>(.*?)</version>", conn.text, re.DOTALL)
                    names = re.findall(r"<name[^>]*>(.*?)</name>", conn.text, re.DOTALL)

                    out = {}
                    out["url"] = url + path
                    out["name"] = names[0]
                    out["version"] = versions[0]
                    if len(names) > 1:
                        out["note"] += f"[Name:There are multiple names identified:({names})]"
                    if len(versions) > 1:
                        out["note"] += f"[Name:There are multiple versions in xml identified:({versions})]"

                    final_out.append(out)

        except Exception as e:
            print(f"Error during retrieving the component xml sites |{url}|{path}|")
            print("Error:" + str(e))

    if len(final_out) == 0:
        return None
    return final_out

# mod_name contains "mod_" prefix
def check_for_module(url, mod_name, user_agent):

    ## for now it is list because of multiple URL types for same module
    final_out = []

    paths = [
        "/modules/" + mod_name + "/" + mod_name + ".xml",
        "/administrator/modules/" + mod_name + "/" + mod_name + ".xml"
    ]

    for path in paths:
        try:
            request_headers = {**custom_headers, "User-Agent": user_agent}
            conn = requests.get(url + path, headers = request_headers, timeout=timeoutconnection, proxies=proxies, verify=False)

            ## Is verifying 200 and content type sufficient ?
            if conn.status_code == 200:
                if "xml" in conn.headers.get("Content-Type", "").lower():

                    ## There are multiple lines with version in the .xml files..
                    ## Some extensions have multuple plg,com,mod with different versions
                    versions = re.findall(r"<version[^>]*>(.*?)</version>", conn.text, re.DOTALL)
                    names = re.findall(r"<name[^>]*>(.*?)</name>", conn.text, re.DOTALL)

                    out = {}

                    out["url"] = url + path
                    out["name"] = names[0]
                    out["version"] = versions[0]
                    if len(names) > 1:
                        out["note"] += f"[Name:There are multiple names identified:({names})]"
                    if len(versions) > 1:
                        out["note"] += f"[Name:There are multiple versions in xml identified:({versions})]"

                    final_out.append(out)

        except Exception as e:
            print(f"Error during retrieving the module xml sites |{url}|{path}|")
            print("Error:" + str(e))

    if len(final_out) == 0:
        return None
    return final_out

# plg_name NOT conains "plg_" prefix
def check_for_plugin(url, plg_name, user_agent):

    final_out = []

    plugin_keywords = ['actionlog', 'acymailing', 'adsmanagercontent', 'ajax', 'authentication', 'blc', 'captcha', 'console', 'content', 'editors', 'editors-xtd', 'eventgallery_pay', 'eventgallery_ship', 'eventgallery_sur', 'extension', 'fields', 'finder', 'hotspots', 'hotspotslinks', 'installer', 'j2store', 'jem', 'jlsitemap', 'jshopping', 'jshoppingcheckout', 'jshoppingorder', 'jshoppingproducts', 'k2', 'osmap', 'pagebuilderck', 'privacy', 'quickicon', 'schuweb_sitemap', 'search', 'slogin_auth', 'slogin_integration', 'solidres', 'solidrespayment', 'system', 'task', 'user', 'vmpayment', 'webservices', 'xmap']

    prefix_url = "/plugins/"
    suffix_url = "/" + plg_name + "/" + plg_name + ".xml"  


    for keyword in plugin_keywords:
        try:
            path = prefix_url + keyword + suffix_url
            request_headers = {**custom_headers, "User-Agent": user_agent}
            conn = requests.get(url + path, headers = request_headers, timeout=timeoutconnection, proxies=proxies, verify=False)
    
            

            ## Is verifying 200 and content type sufficient ?
            if conn.status_code == 200:
                if "xml" in conn.headers.get("Content-Type", "").lower():

                    ## There are multiple lines with version in the .xml files..
                    ## Some extensions have multuple plg,com,mod with different versions
                    versions = re.findall(r"<version[^>]*>(.*?)</version>", conn.text, re.DOTALL)
                    names = re.findall(r"<name[^>]*>(.*?)</name>", conn.text, re.DOTALL)

                    out = {}

                    out["url"] = url + path
                    out["name"] = names[0]
                    out["version"] = versions[0]
                    if len(names) > 1:
                        out["note"] += f"[Name:There are multiple names identified:({names})]"
                    if len(versions) > 1:
                        out["note"] += f"[Name:There are multiple versions in xml identified:({versions})]"

                    final_out.append(out)

        except Exception as e:
            print(f"Error during retrieving the module xml sites |{url}|{path}|")
            print("Error:" + str(e))

    if len(final_out) == 0:
        return None
    return final_out 



def process_redirs(conn):

    redir_urls = []
    final_urls = []

    ## redir_urls contains all the redirects
    ## stripping of '/' because request.get() returns always 1 url with / at the end
    if conn.history:
        for resp in conn.history:
            if resp.url[-1:] == "/":
                redir_urls.append(resp.url[:-1])
            else:
                redir_urls.append(resp.url)

    if conn.url[-1:] == '/':
        redir_urls.append(conn.url[:-1])
    else:
        redir_urls.append(conn.url)

    ## the protocol and domain is stripped from redirects - https://domain.com/en/shop/{module} dont work but https://domain.com/{module} does
    for url in redir_urls:
        final_urls.append(url)
        try:
            parsed_url = urlparse(url)

            scheme = parsed_url.scheme
            netloc = parsed_url.netloc

            final_urls.append(f"{scheme}://{netloc}")
        except Exception as e:
            print(f"Error parsing URL: {e}")

    return list(set(final_urls))

def check_index(url, user_agent):

    scanner_output = {
        "redirect_urls": [],
        "components": {},
        "modules": {},
        # "packages": []
        # "libraries": []
        "plugins": {}
        # "templates": []

    }
    try:
        request_headers = {**custom_headers, "User-Agent": user_agent}
        conn = requests.get(url, headers=request_headers, timeout=timeoutconnection, proxies=proxies, verify=False)
        final_urls = process_redirs(conn)

        print(f"{len(final_urls)} urls found:\n{final_urls}")
        scanner_output['redirect_urls'] = final_urls

        if conn.status_code == 200:
            index_components, index_modules, index_packages, index_plugins, index_templates = blob_ext_identification(conn, final_urls, user_agent)

            # print(index_components)
            # print(index_modules)
            # print(index_packages)
            # print(index_plugins)
            # print(index_templates)

            if len(index_modules) > 0:                     
                for uniq_mod in index_modules:              
                    scanner_output["modules"][uniq_mod] = []
                    for val in final_urls:
                        tmp_out = check_for_module(val, uniq_mod, user_agent)
                        if tmp_out:
                            mod_name = tmp_out[0]['name']
                            mod_version = tmp_out[0]['version']
                            mod_url = tmp_out[0]['url']

                            # Check if the same module (name + version) already exists
                            existing_entry = next(
                                (entry for entry in scanner_output["modules"][uniq_mod] 
                                if entry["name"] == mod_name and entry["version"] == mod_version), 
                                None
                            )

                            if existing_entry:
                                # If name & version match, just add the URL
                                if mod_url not in existing_entry['urls']:
                                    existing_entry['urls'].append(mod_url)
                            else:
                                # If name or version is different, create a new entry
                                scanner_output["modules"][uniq_mod].append({
                                    'name': mod_name,
                                    'version': mod_version,
                                    'urls': [mod_url]  # Store initial URL
                                })

            if len(index_components) > 0:
                for uniq_comp in index_components:
                    scanner_output["components"][uniq_comp] = []
                    for val in final_urls:
                        tmp_out = check_for_component(val, uniq_comp, user_agent)
                        if tmp_out:
                            comp_name = tmp_out[0]['name']
                            comp_version = tmp_out[0]['version']
                            comp_url = tmp_out[0]['url']

                            # Check if the same component (name + version) already exists
                            existing_entry = next(
                                (entry for entry in scanner_output["components"][uniq_comp]
                                if entry["name"] == comp_name and entry["version"] == comp_version),
                                None
                            )

                            if existing_entry:
                                # If name & version match, just add the URL
                                if comp_url not in existing_entry['urls']:
                                    existing_entry['urls'].append(comp_url)
                            else:
                                # If name or version is different, create a new entry
                                scanner_output["components"][uniq_comp].append({
                                    'name': comp_name,
                                    'version': comp_version,
                                    'urls': [comp_url]  # Store initial URL
                                })



            # if len(index_plugins) > 0:
            #     for uniq_plugin in index_plugins:
            #         scanner_output["plugins"][uniq_plugin] = []
            #         for val in final_urls:
            #             tmp_out = check_for_plugin(val, uniq_plugin, user_agent)
            #             if tmp_out:
            #                 plugin_name = tmp_out[0]['name']
            #                 plugin_version = tmp_out[0]['version']
            #                 plugin_url = tmp_out[0]['url']

            #                 # Check if the same plugin (name + version) already exists
            #                 existing_entry = next(
            #                     (entry for entry in scanner_output["plugins"][uniq_plugin]
            #                     if entry["name"] == plugin_name and entry["version"] == plugin_version),
            #                     None
            #                 )

            #                 if existing_entry:
            #                     # If name & version match, just add the URL
            #                     if plugin_url not in existing_entry['urls']:
            #                         existing_entry['urls'].append(plugin_url)
            #                 else:
            #                     # If name or version is different, create a new entry
            #                     scanner_output["plugins"][uniq_plugin].append({
            #                         'name': plugin_name,
            #                         'version': plugin_version,
            #                         'urls': [plugin_url]  # Store initial URL
            #                     })

        else:
            print("There was problem retriewing the index page")
            print("Status code: " + str(conn.status_code))

    except Exception as e:
        print(e)
        return None

    # print(scanner_output)


    print_scanner_results_with_extensions(scanner_output, "extensions.json")


def extension_enum(url, user_agent, rate_limit):
    with open('extensions-files.json', 'r', encoding='utf-8') as f:
        extensions = json.load(f)

    # Initialize counters
    total_com_files = 0
    total_mod_files = 0
    total_plugins = 0
    total_packages = 0
    total_libs = 0

    # Iterate through each extension
    for ext in extensions:
        # Count all URLs in each category
        total_com_files += sum(len(paths) for paths in ext.get("com_files", {}).values())
        total_mod_files += sum(len(paths) for paths in ext.get("mod_files", {}).values())
        total_plugins += sum(len(paths) for paths in ext.get("plugins", {}).values())
        total_packages += sum(len(paths) for paths in ext.get("packages", {}).values())
        total_libs += sum(len(paths) for paths in ext.get("lib", {}).values())
        total_urls = total_com_files + total_mod_files + total_plugins + total_packages + total_libs

    # Print the results
    print("**Count of URLs in Each Category:**")
    print(f"Components (com_files): {total_com_files}")
    print(f"Modules (mod_files): {total_mod_files}")
    print(f"Plugins: {total_plugins}")
    print(f"Packages: {total_packages}")
    print(f"Libraries (lib): {total_libs}")
    print(f"Total number of URLs to try:{total_urls}")


def main(argv):
    # Arguments parsing
    try:
        parser = argparse.ArgumentParser(description="Joomla Scanner - Scans Joomla sites for version identification.")

        parser.add_argument("-u", "--url", action="store", dest="url", required=True,
                            help="The Joomla URL/domain to scan. Example: https://example.com")

        parser.add_argument("--user-agent", action="store", dest="user_agent", default = "Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
                            help="Specify a custom User-Agent string")

        parser.add_argument("--rate-limit", action="store", dest="rate_limit", type=int, default=0,
                            help="Set the number of requests per second (default: 0, meaning no limit).")

        parser.add_argument("--scan-type", action="store", dest="scan_type", choices=["light", "invasive"], default="light",
                            help="Select scan type: 'light' (default) - Scans only the HTML blob and identifies versions by common URL patterns for subextension types. "
                                 "'invasive' - Enumerates URLs for every extension from a list containing all Joomla versions.")

        arguments = parser.parse_args()
    except:
        sys.exit(1)

    # Validate URL
    url = arguments.url
    if not url.startswith(("http://", "https://")):
        print("Insert http:// or https:// prefix")
        sys.exit(1)

    # Remove trailing slash if present
    url = url.rstrip("/")

    # Extract optional parameters
    user_agent = arguments.user_agent
    rate_limit = arguments.rate_limit
    scan_type = arguments.scan_type

    if scan_type == "light":
        check_index(url, user_agent)
    elif scan_type == "invasive":
        extension_enum(url, user_agent, rate_limit)

if __name__ == "__main__":
    main(sys.argv[1:])