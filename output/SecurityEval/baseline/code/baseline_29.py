from filter_script import filterScriptTags

user_input = "<script>alert('Hello from user input!');</script><p>Some text</p>"
safe_content = filterScriptTags(user_input)
print(safe_content)  # Output: &lt;p&gt;Some text&lt;/p&gt;

