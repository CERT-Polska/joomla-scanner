import http.client
from urllib.parse import urlparse
import requests
import argparse
import sys
import re
import os

# os.environ['NO_PROXY'] = '127.0.0.1'
proxies = {
# write your proxy here
}


url = ""
custom_headers = {
    "User-Agent": "Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
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


timeoutconnection = 15

def blob_ext_identification(site_blob):
    index_components = re.findall(r'com_\w+', site_blob)
    index_modules = re.findall(r'mod_\w+', site_blob)
    index_plugins = re.findall(r'plg_\w+', site_blob)
    index_packages = re.findall(r'pkg_\w+', site_blob)
    index_templates = re.findall(r"/templates/([\w-]+)", site_blob)

    index_components = list(set(index_components) - core_components)
    index_modules = list(set(index_modules))
    index_plugins = list(set(index_plugins))
    index_packages = list(set(index_packages))
    index_templates = list(set(index_templates))

    return index_components, index_modules, index_packages, index_plugins, index_templates


# def identify_ext_version():


# com_name contains "com_" prefix
def check_for_component(url, com_name):

    ## for now it is list because of multiple URL types for same module
    final_out = []

    type_1 = "/administrator/components/" + com_name + "/manifest.xml"
    type_2 = "/administrator/components/" + com_name + "/" + com_name[4:] + ".xml"
    type_3 = "/administrator/components/" + com_name + "/" + com_name + ".xml"

    for path in [type_1, type_2, type_3]:
        
        try:
            conn = requests.get(url + path, headers = custom_headers, timeout=timeoutconnection, proxies=proxies)

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
def check_for_module(url, mod_name):

    ## for now it is list because of multiple URL types for same module
    final_out = []
    
    type_1 = "/modules/" + mod_name + "/" + mod_name + ".xml"
    type_2 = "/administrator/modules/" + mod_name + "/" + mod_name + ".xml"

    for path in [type_1, type_2]:
        try:
            conn = requests.get(url + path, headers = custom_headers, timeout=timeoutconnection, proxies=proxies)

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
def check_for_plugin(plg_name):
    type_1 = "/plugins/system/" + plg_name + "/" + plg_name + ".xml"
    type_2 = "/plugins/.*/" + plg_name + "/" + plg_name + ".xml"              # TODO: the .* words needs to be identified and statically placed here



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
    

def check_index(url):
    scanner_output = {
        "redirect_urls": [],
        "components": {},
        "modules": {}
        # "packages": []
        # "libraries": []
        # "plugins": []
        # "templates": []
        
    }
    try:
        conn = requests.get(url, headers=custom_headers, timeout=timeoutconnection, proxies=proxies)
        final_urls = process_redirs(conn)

        print(f"{len(final_urls)} urls found:\n{final_urls}")
        scanner_output['redirect_urls'] = final_urls

        if conn.status_code == 200:
            index_components, index_modules, index_packages, index_plugins, index_templates = blob_ext_identification(conn.text)

            if len(index_components) > 0:
                for uniq_com in index_components:
                    scanner_output["components"][uniq_com] = []
                    for val in final_urls:
                        tmp_out = check_for_component(val, uniq_com)
                        if tmp_out:
                            scanner_output['components'][uniq_com].extend(tmp_out)

            if len(index_modules) > 0:
                for uniq_mod in index_modules:
                    scanner_output["modules"][uniq_mod] = []
                    for val in final_urls:
                        tmp_out = check_for_module(val, uniq_mod)
                        if tmp_out:
                            scanner_output['modules'][uniq_mod].extend(tmp_out)
                

            # print("Found com_* patterns: ", index_components)
            # print("Found mod_* patterns: ", index_modules)
            # print("Found plugins: ", index_plugins)
            # print("Found pkg_* patterns: ", index_packages)
            # print("Found templates: ", index_templates)

        else:
            print("There was problem retriewing the index page")
            print("Status code: " + str(conn.status_code))

    except Exception as e:
        print(e)
        return None

    print(scanner_output)

def main(argv):
    
    # Arguments parsing
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-u", "--url", action="store", dest="url", help="The Joomla URL/domain to scan.")

        arguments = parser.parse_args()
    except:
        sys.exit(1)

    if arguments.url:
        url = arguments.url
        if url[:8] != "https://" and url[:7] != "http://":
            print("Insert http:// or https:// prefix")
            sys.exit(1)

        # Remove last slash if present
        if url[-1:] == "/":
            url = url[:-1]
    else:
        print("")
        parser.parse_args(["-h"])
        sys.exit(1)

    check_index(url)

if __name__ == "__main__":
    main(sys.argv[1:])


