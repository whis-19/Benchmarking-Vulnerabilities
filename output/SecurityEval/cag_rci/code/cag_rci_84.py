html
{# my_template.html #}
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://trusted.cdn.com;">
  <title>My Template</title>
</head>
<body>
  <p>Name: {{ my_model.name }}</p>  {# Automatically escaped #}
  <p>Value: {{ my_model.value }}</p> {# Automatically escaped #}
</body>
</html>

