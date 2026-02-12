html+jinja
        <script>
          var result = {{ result | tojson | safe }}; // Use tojson filter
          console.log(result);
        </script>

