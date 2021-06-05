---
name: Bug report
about: Create a report to help us improve CrackQ
title: Error with X [BUG]
labels: ''
assignees: ''

---

**Prerequisites**
Enable debugging:
sudo docker exec -it crackq /bin/sed -i 's/INFO/DEBUG/g' /opt/crackq/build/crackq/log_config.ini

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Debug output**
*Include the console output with debugging enabled
*Include HTTP request and response data (body only) where relevant

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Additional context**
Add any other context about the problem here.
