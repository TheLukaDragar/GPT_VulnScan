# import os
# import fnmatch
# import subprocess
# from jinja2 import Template
# from pathlib import Path
# from pathspec import PathSpec
# from pathspec.patterns import GitWildMatchPattern
# from typing import List
# import litellm


# class VulnScan:
#     def __init__(self, path: str, model: str = "gpt-4o-2024-08-06", num_vuln: int = 7):
#         self.path = path
#         self.model = model
#         self.num_vuln = num_vuln
#         self.description: str = ""
#         self.tags: List[str] = []
#         self.boilerplate: str = ""
#         self.issues: List[str] = []
#         self.output: str = ""

#     def scan(self) -> None:
#         context = format_gpt(self.path)

#         # Get description and tags
#         response = self._get_completion(TASK1, context)
#         self._parse_description_and_tags(response)

#         # Get boilerplate code
#         context += "\nHere is a description of the service:\n"
#         response = self._get_completion(TASK2, context)
#         self.boilerplate = response

#         # Get vulnerabilities
#         context += "\nHere is how to interact with the service:\n"
#         response = self._get_completion(
#             Template(TASK3).render(kaos=KAOS, num_vuln=self.num_vuln), context
#         )
#         self._parse_issues(response)

#     def _get_completion(self, task: str, context: str) -> str:
#         template = Template(PROMPT)
#         formatted_prompt = template.render(context=context)

#         response = litellm.completion(
#             model=self.model,
#             messages=[
#                 {"role": "system", "content": formatted_prompt},
#                 {"role": "user", "content": task},
#             ],
#         )

#         self.output += response.choices[0].message.content + "\n"
#         return response.choices[0].message.content

#     def _parse_description_and_tags(self, response: str) -> None:
#         if "tags:" in response:
#             parts = response.split("Tags:", 1)
#         elif "Tags:" in response:
#             parts = response.split("Tags:", 1)
#         else:
#             raise ValueError("No tags found, restart the scan")
#         self.description = parts[0].strip()
#         if len(parts) > 1:
#             self.tags = [tag.strip() for tag in parts[1].split(",")]

#     def _parse_issues(self, response: str) -> None:
#         self.issues = [
#             x.strip() for x in response.split("### Vulnerability") if x.strip()
#         ]

#     def __repr__(self) -> str:
#         return f"VulnScan(path='{self.path}', model='{self.model}', num_vuln={self.num_vuln})"

#     def __str__(self) -> str:
#         return (
#             f"VulnScan for {self.path}\n"
#             f"Description: {self.description[:50]}...\n"
#             f"Tags: {', '.join(self.tags)}\n"
#             f"Number of issues found: {len(self.issues)}"
#         )


# KAOS = """def exploit(flag_id=None):
#     session = get_http_session()

#     # TODO: your exploit

#     #res = session.get(f'http://{get_team_ip()}:1234/')
#     #extract_flag(res.content, flag_id)"""
# PROMPT = """**Role:** You are a cybersecurity expert specializing in finding security vulnerabilities and performing red team tasks.

# You are given the source code of a vulnerable application in /service/. Here is the source code:

# {{ context }}
# """
# TASK1 = """Your first task is to provide a 1 paragraph description of the application. Note the technologies used, and what skills someone might require in order to find vulnerabilities in this service. After the paragraph, add some tags. Like this:
# Tags: python, javascript, fastapi, postgres"""

# TASK2 = """Your first task is to implement all the interaction possible with the service. Use Python. If the service is HTTP, use the requests module with Session. If it's TCP, use pwntools.
# If it's something else, please specify. But you need to implement all the interaction.
# Only use one single file. Make sure your response is Markdown.
# Prefer procedural code over OOP and pass state via parameters. That makes it easier to copy-paste for later.
# """

# TASK3 = """Given all the previous information. Your task is to find all the vulnerabilities in the service.
# Focus on vulnerabilities that require no user interaction (IDOR, LFI, RCE, SQLi, SSRF, XXE, Deserialization, etc). and don't spend time on XSS or CSRF.
# Since this is a competition, use this template Python script to get points for your exploit:
# ```exploit.py
# {{ kaos }}
# ```
# For each vulnerability, report the code that is responsible for the vulnerability, the vulnerability summary and the exploit code.
# You must always do that, even if the exploit is trivial (e.g. a file read). YOU MUST ALWAYS INCLUDE THE EXPLOIT CODE, WITH AN EXAMPLE BASED ON THE TEMPLATE. REUSE PARTS THAT INTERACT WITH THE SERVICE (by copy and pasting).
# Make sure that the vulnerability is legit, by double checking the code from the repository that is responsible for the vulnerability.
# You must find at least {{ num_vuln }} vulnerabilities.
# Follow this template:

# ### Vulnerability <index>: <title>

# For each vulnerable code snippet {
# <path to snippet>
# ```code-language
# <vulnerable code snippet>
# ```
# }

# <vulnerability description>

# <exploit code>
# """

# default_exclude = [
#     ".git",
#     ".gitignore",
#     ".DS_Store",
#     ".svn",
#     ".hg",
#     ".idea",
#     ".vscode",
#     ".settings",
#     ".pytest_cache",
#     "__pycache__",
#     "node_modules",
#     "vendor",
#     "build",
#     "dist",
#     "bin",
#     "logs",
#     "log",
#     "tmp",
#     "temp",
#     "coverage",
#     "venv",
#     "env",
#     "*.html",
#     "*.css",
#     "*.svg",
#     "manifest.json",
#     "package-lock.json",
#     "yarn.lock",
#     ".prettierignore",
#     ".gitignore",
#     "go.sum",
# ]


# def find_text_files(folder_path: str) -> List[str]:
#     """
#     Find all text files (< 100KB) in the given folder path, respecting .gitignore rules and default exclusions using DFS.

#     Args:
#         folder_path (str): The path to the folder to search.

#     Returns:
#         List[str]: A list of paths to text files found.
#     """
#     text_files = []
#     root_path = Path(folder_path).resolve()

#     def dfs(current_path: Path, gitignore_spec: PathSpec):
#         # Read .gitignore in the current directory and update the spec
#         current_gitignore = current_path / ".gitignore"
#         if current_gitignore.exists():
#             with current_gitignore.open("r") as f:
#                 new_patterns = f.readlines()
#             gitignore_spec = PathSpec.from_lines(
#                 GitWildMatchPattern, new_patterns + gitignore_spec.patterns
#             )

#         for item in current_path.iterdir():
#             relative_path = item.relative_to(root_path)
#             rel_cur = item.relative_to(current_path)
#             if any(
#                 fnmatch.fnmatch(str(relative_path), exclude)
#                 or str(relative_path) == exclude
#                 for exclude in default_exclude
#             ):
#                 continue

#             if any(
#                 fnmatch.fnmatch(str(rel_cur), exclude) or str(rel_cur) == exclude
#                 for exclude in default_exclude
#             ):
#                 continue

#             if gitignore_spec.match_file(
#                 str(relative_path)
#             ) or gitignore_spec.match_file(str(rel_cur)):
#                 continue

#             if item.is_dir():
#                 dfs(item, gitignore_spec)
#             elif item.is_file():
#                 text_files.append(str(item))

#     # Start DFS with an empty gitignore spec
#     initial_gitignore_spec = PathSpec.from_lines(GitWildMatchPattern, default_exclude)
#     dfs(root_path, initial_gitignore_spec)

#     return text_files


# def is_text_file(file_path: str, max_size: int = 100 * 1024) -> bool:
#     """
#     Check if a file is a text file by attempting to decode it as UTF-8
#     and checking its size.

#     Args:
#         file_path (str): The path to the file to check.
#         max_size (int): The maximum file size in bytes (default: 10KB).

#     Returns:
#         bool: True if the file is a text file and smaller than max_size, False otherwise.
#     """
#     try:
#         if os.path.getsize(file_path) > max_size:
#             return False

#         with open(file_path, "rb") as f:
#             content = f.read()
#             content.decode("utf-8")
#         return True
#     except (UnicodeDecodeError, IOError):
#         return False


# def run_file(path: str) -> str:
#     result = subprocess.run(["file", path], capture_output=True, text=True)
#     return result.stdout


# def format_gpt(folder_to_search: str, service_root: str = "/service/") -> str:
#     output = ""
#     root = Path(folder_to_search).resolve()

#     for file in find_text_files(folder_to_search):
#         path = Path(file).resolve().relative_to(root)
#         output += "```" + service_root + str(path) + "\n"
#         if is_text_file(file):
#             with open(file, "r") as f:
#                 output += f.read()
#         else:
#             output += run_file(file)
#         output += "\n```\n\n"

#     return output


# if __name__ == "__main__":
#     import argparse
#     import sys

#     parser = argparse.ArgumentParser(
#         description="Perform vulnerability scan on a specified folder."
#     )
#     parser.add_argument("folder_path", help="Path to the folder to scan")
#     args = parser.parse_args()

#     vulnscan = VulnScan(args.folder_path)
#     vulnscan.scan()

#     print(vulnscan.output)

#     print("=== Parsed output ===", file=sys.stderr)
#     print("Description:", vulnscan.description, file=sys.stderr)
#     print("Tags:", vulnscan.tags, file=sys.stderr)
#     print("Boilerplate:", vulnscan.boilerplate, file=sys.stderr)
#     print("Vulns:", file=sys.stderr)
#     for issue in vulnscan.issues:
#         print(issue, file=sys.stderr)


#
# write txt

import datetime

import argparse
import os

parser = argparse.ArgumentParser(description="get folder path")
parser.add_argument("folder_path", type=str, help="folder path to scan")
args = parser.parse_args()

print(args.folder_path)

print("Date is: ", datetime.datetime.now())


with open("vulnscan_output.txt", "w") as text_file:
    text_file.write("Date is: " + str(datetime.datetime.now()) + "\n")
    # write ls of folder
    text_file.write("ls of folder: \n")
    text_file.write(os.popen("ls " + args.folder_path).read())
