## Detection script that reads normalized events from our dynamo db table named anomai_events and then outputs the incidents to out/incidents.json file.

To run this script:

```
./run_detection.py
```
Or
```
python3 run_detection.py
```

But if you notice from out/incidents.json file, this json file is not that good for UI so we need another script to convert this json file to better format for UI.

## Convertor script that reads out/incidents.json file then converts it to better format and writes to out/incidents_api.json

To run the script:
```
./convert_incidents_to_api.py
```
Or
```
python3 convert_incidents_to_api.py
```

Finally, rather than reading local file it's better the UI reads data from an API.

## Using flask, an API created for UI
To run:
```
python3 serve_incidents_api_flask.py
```
