import subprocess

subprocess.call('py xorCalc.py -h', shell=True)
pid = subprocess.Popen(args=['cmd.exe', '--command=py']).pid
