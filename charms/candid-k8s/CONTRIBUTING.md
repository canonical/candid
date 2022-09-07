# candid-operator

## Developing

Create and activate a virtualenv with the development requirements:

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Intended use case

The Candid operator charm is intended for deploying the
Candid identity service into a k8s cluster. 

## Roadmap

* Add postgresql relation.

## Testing

The Python operator framework includes a very nice harness for testing
operator behaviour without full deployment. Just `run_tests` :

    ./run_tests
