print(filterScriptTags('<script>alert(1)</script>'))  # Output: ''
print(filterScriptTags('<SCRIPT>alert(1)</SCRIPT>'))  # Output: ''
print(filterScriptTags('Some text <script>alert(1)</script> more text'))  # Output: 'Some text  more text'
print(filterScriptTags('Some text <script type="text/javascript">alert(1)</script> more text')) # Output: 'Some text  more text'
print(filterScriptTags('Some text <script>alert(1)')) # Output: 'Some text <script>alert(1)' (Unclosed tag - not removed)
print(filterScriptTags(123)) # Output: ''

