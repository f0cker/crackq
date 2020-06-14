I'm looking for help with this project, so please consider contributing if you would like to see some of the planned features implemented sooner. Please read the below guide before making a PR.

# Style Guide

The style used is what I call PEP8ish. I follow [PEP8](https://www.python.org/dev/peps/pep-0008/), but use it more as a guideline than a strict style. Particularly when it comes to line length, 80 isn’t always enough so if it's more readable with a longer line, then by all means go for it. I’m using various linters like Flake8, and Bandit. Try to write in a ‘Pythonic’ way that’s easily readable and generally follow the Zen of Python (https://www.python.org/dev/peps/pep-0020/).

No Shell commands! I’ve gone to great lengths to ensure no shells were used during development, I will reject any PRs with dirty shell commands (spits). All Hashcat interaction is done via libhashcat (see PyHashcat). I’ve used os.xx occasionally when I’ve had to, but even that lib I’m using sparingly.

There’s a fair amount of cleanup required right now to meet the styling standards and improve code quality all round, I’ve highlighted areas for review/todo with ###***.

The test coverage is not good currently, if you’re looking to get into helping with this project and you don’t know where to start, this could be a good place to start. Writing some additional tests would likely be a good way to get to know the code base (see /crackq/tests/).

Otherwise look in the Project Roadmap, there are plenty of tasks in there, both simple and complicated. Adding more Hashcat options is a simple one, I’ve done all the hard work so it’s just a case of feeding these up from PyHashcat to the REST API, and then adding to the GUI. There are some previous commits you can follow to do this.

Documentation is in the NumPy style mostly, but it needs a lot of work before it can be used to generate complete documentation.

String interpolation uses the '{}'.format(var) style, but logging/logger should be used for printing debug output.

# GUI Development

I have a private Git repo with the Vue JS front-end. I haven’t released it publicly yet, but I will be releasing it soon. In the meantime, if you need access to it just ping me a message and I will allow you access to the Gitlab repo.

# Development Environment

There isn’t much needed to get setup with a dev env. I use the the following 2 install steps:
```
sudo ./install docker/opencl/ubuntu
sudo docker-compose -f docker-compose.dev.yml up —build
```

Then you can modify the Flask application in ./crackq from outside the docker container. The majority of your time will be spent in cq_api.py and run_hashcat.py.


If you are performing dev work you will likely want to modify the Circus process manager setup so that you are able to view all errors from Flask directly. CrackQ uses Circus this to manage the 4 processes that run as part of the application. Namely the Flask app, 2 workers that handle running the jobs from the Redis queue and the Hashcat brain server/service. The Flask application uses Gunicorn as a WSGI interface, this is not great to use when debugging as it doesn't print all errors to stdout very well. So the dev docker-compose file (docker-compose.dev.yml) is setup to run the Flask app with the debug WSGI Werkzeug, by using the dev version of the Circus ini file. You can modify the relevant line in the docker-compose file to switch back to the production config (see the commented line).
