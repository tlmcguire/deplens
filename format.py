#!/usr/bin/env python3
"""
Python Comment Removal Script

This script removes various types of comments from Python files while preserving:
- Docstrings (triple-quoted strings at the beginning of modules, classes, functions)
- String literals that contain # characters
- Comments inside string literals

Types of comments removed:
- Single-line comments (# comment)
- Inline comments (code  # comment)
- Multi-line comments using # on each line
"""

import re
import sys
import os
from typing import List, Tuple


class CommentRemover:
    def __init__(self):
        # Regex patterns for different types of strings and comments
        self.string_patterns = [
            r'"""[\s\S]*?"""',  # Triple double quotes (multiline)
            r"'''[\s\S]*?'''",  # Triple single quotes (multiline)
            r'"(?:[^"\\]|\\.)*"',  # Double quoted strings
            r"'(?:[^'\\]|\\.)*'",  # Single quoted strings
        ]
        
        # Combined pattern to match all strings
        self.string_pattern = '|'.join(f'({pattern})' for pattern in self.string_patterns)
        
    def remove_comments_regex(self, source: str) -> str:
        """
        Remove comments using regex while preserving strings and docstrings.
        """
        lines = source.split('\n')
        cleaned_lines = []
        
        in_multiline_string = False
        multiline_delimiter = None
        
        for line in lines:
            cleaned_line = self._process_line_for_comments(line, in_multiline_string, multiline_delimiter)
            
            # Update multiline string state
            in_multiline_string, multiline_delimiter = self._update_multiline_state(line, in_multiline_string, multiline_delimiter)
            
            # Only add non-empty lines or lines that originally had content
            if cleaned_line.strip() or not line.strip().startswith('#'):
                cleaned_lines.append(cleaned_line)
        
        return '\n'.join(cleaned_lines)
    
    def _update_multiline_state(self, line: str, in_multiline: bool, delimiter: str) -> Tuple[bool, str]:
        """
        Update the state of multiline string parsing.
        """
        if in_multiline:
            # Look for closing delimiter
            if delimiter in line:
                # Find all occurrences to handle multiple strings on one line
                parts = line.split(delimiter)
                if len(parts) > 1:
                    # Check if we have an odd or even number of delimiters
                    # Odd means we're closing the string
                    if len(parts) % 2 == 0:
                        return False, None
            return True, delimiter
        else:
            # Look for opening triple quotes
            for delim in ['"""', "'''"]:
                if delim in line:
                    # Count occurrences
                    count = line.count(delim)
                    if count % 2 == 1:  # Odd number means we're opening a multiline string
                        return True, delim
            return False, None
    
    def _process_line_for_comments(self, line: str, in_multiline: bool, delimiter: str) -> str:
        """
        Process a single line to remove comments while preserving strings.
        """
        if in_multiline:
            # We're inside a multiline string, don't process comments
            return line
            
        result = []
        i = 0
        in_string = False
        string_char = None
        escape_next = False
        
        while i < len(line):
            char = line[i]
            
            if escape_next:
                result.append(char)
                escape_next = False
                i += 1
                continue
                
            if char == '\\' and in_string:
                escape_next = True
                result.append(char)
                i += 1
                continue
                
            if not in_string:
                if char in ['"', "'"]:
                    # Check for triple quotes
                    if i + 2 < len(line) and line[i:i+3] == char * 3:
                        in_string = True
                        string_char = char * 3
                        result.append(line[i:i+3])
                        i += 3
                        continue
                    else:
                        in_string = True
                        string_char = char
                        result.append(char)
                        i += 1
                        continue
                elif char == '#':
                    # Found a comment outside of string, remove rest of line
                    break
                else:
                    result.append(char)
                    i += 1
                    continue
            else:
                # We're inside a string
                if (string_char == char or 
                    (len(string_char) == 3 and i + 2 < len(line) and line[i:i+3] == string_char)):
                    # End of string
                    if len(string_char) == 3:
                        result.append(line[i:i+3])
                        i += 3
                    else:
                        result.append(char)
                        i += 1
                    in_string = False
                    string_char = None
                else:
                    result.append(char)
                    i += 1
        
        # Remove trailing whitespace but preserve leading whitespace
        result_str = ''.join(result).rstrip()
        return result_str
    
    def _is_likely_docstring(self, line: str, previous_lines: List[str]) -> bool:
        """
        Heuristic to determine if a triple-quoted string is likely a docstring.
        """
        stripped = line.strip()
        if not (stripped.startswith('"""') or stripped.startswith("'''")):
            return False
            
        # Check if this follows a function/class definition
        for prev_line in reversed(previous_lines[-5:]):  # Check last 5 lines
            prev_stripped = prev_line.strip()
            if prev_stripped:
                if (prev_stripped.startswith('def ') or 
                    prev_stripped.startswith('class ') or
                    prev_stripped.startswith('async def ')):
                    return True
                elif prev_stripped.endswith(':'):
                    return True
                else:
                    break
                    
        # Check if it's at the beginning of the file (module docstring)
        non_empty_lines = [l for l in previous_lines if l.strip()]
        if len(non_empty_lines) == 0:
            return True
            
        return False
    
    def format_file(self, file_path: str) -> str:
        """
        Remove comments from a Python file.
        
        Args:
            file_path: Path to the Python file
        
        Returns:
            Cleaned source code
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                source = f.read()
        
        return self.remove_comments_regex(source)
    
    def format_directory(self, directory: str, dry_run: bool = False, backup: bool = True) -> None:
        """
        Remove comments from all Python files in a directory recursively.
        
        Args:
            directory: Directory path
            dry_run: If True, only show what would be changed
            backup: If True, create .bak files
        """
        python_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        print(f"Found {len(python_files)} Python files")
        
        for file_path in python_files:
            try:
                print(f"Processing: {file_path}")
                
                # Read original content
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        original_source = f.read()
                except UnicodeDecodeError:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        original_source = f.read()
                
                cleaned_source = self.remove_comments_regex(original_source)
                
                if original_source != cleaned_source:
                    if dry_run:
                        print(f"  Would modify: {file_path}")
                        # Show a preview of changes
                        original_lines = original_source.count('\n') + 1
                        cleaned_lines = cleaned_source.count('\n') + 1
                        print(f"    Lines: {original_lines} -> {cleaned_lines}")
                    else:
                        if backup:
                            backup_path = file_path + '.bak'
                            with open(backup_path, 'w', encoding='utf-8') as f:
                                f.write(original_source)
                        
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(cleaned_source)
                        print(f"  Modified: {file_path}")
                else:
                    print(f"  No changes: {file_path}")
                    
            except Exception as e:
                print(f"  Error processing {file_path}: {e}")


def test_comment_removal():
    """
    Test the comment removal functionality with various scenarios.
    """
    test_cases = [
        # Test case 1: Simple comment
        '''# This is a comment
print("Hello World")
''',
        
        # Test case 2: Inline comment
        '''x = 5  # This is an inline comment
print(x)
''',
        
        # Test case 3: String with # character
        '''print("This # is not a comment")
# But this is a comment
''',
        
        # Test case 4: Triple quoted string (docstring)
        '''def function():
    """This is a docstring and should be preserved."""
    x = 1  # This comment should be removed
    return x
''',
        
        # Test case 5: Multiple line comments
        '''# Comment 1
# Comment 2
def func():
    # Internal comment
    return 42  # Inline comment
''',
        
        # Test case 6: Mixed quotes and comments
        '''text = "He said 'hello' to me"  # This is a comment
other = 'She said "hi" back'
# Another comment
''',
        
        # Test case 7: Multiline string with # inside
        '''
multiline = """
This is a multiline string
# This should be preserved
with multiple lines
"""
# This comment should be removed
''',
        
        # Test case 8: Complex nested quotes
        '''
text1 = "String with 'single' quotes"  # Remove this
text2 = 'String with "double" quotes'  # Remove this too
text3 = """Triple quoted with # hash"""  # Remove this
''',
    ]
    
    remover = CommentRemover()
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print("Original:")
        print(repr(test_case))
        
        print("\nRegex method:")
        result_regex = remover.remove_comments_regex(test_case)
        print(repr(result_regex))


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 format.py <file_or_directory>")
        print("       python3 format.py --test")
        sys.exit(1)
    
    if sys.argv[1] == "--test":
        test_comment_removal()
        return
    
    path = sys.argv[1]
    remover = CommentRemover()
    
    if os.path.isfile(path):
        # Single file
        try:
            # Read original content
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    original_source = f.read()
            except UnicodeDecodeError:
                with open(path, 'r', encoding='latin-1') as f:
                    original_source = f.read()
            
            cleaned_source = remover.remove_comments_regex(original_source)
            
            if original_source != cleaned_source:
                # Create backup
                backup_path = path + '.bak'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_source)
                print(f"Created backup: {backup_path}")
                
                # Write cleaned version
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(cleaned_source)
                print(f"Processed: {path}")
            else:
                print(f"No changes needed: {path}")
                
        except Exception as e:
            print(f"Error processing {path}: {e}")
            
    elif os.path.isdir(path):
        # Directory - process all Python files
        remover.format_directory(path, dry_run=False, backup=True)
    else:
        print(f"Error: {path} is not a valid file or directory")
        sys.exit(1)


if __name__ == "__main__":
    main()
