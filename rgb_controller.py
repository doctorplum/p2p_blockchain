#libraries
import RPi.GPIO as GPIO
from time import sleep
#disable warnings (optional)
GPIO.setwarnings(False)
#Select GPIO Mode
GPIO.setmode(GPIO.BCM)
#set red,green and blue pins
redPin = 12
greenPin = 13
bluePin = 19
#set pins as outputs
GPIO.setup(redPin,GPIO.OUT)
GPIO.setup(greenPin,GPIO.OUT)
GPIO.setup(bluePin,GPIO.OUT)

low = GPIO.HIGH
high = GPIO.LOW

def turn_off():
    GPIO.output(redPin,high)
    GPIO.output(greenPin,high)
    GPIO.output(bluePin,high)
    
def white():
    GPIO.output(redPin,low)
    GPIO.output(greenPin,low)
    GPIO.output(bluePin,low)
    
def red():
    GPIO.output(redPin,low)
    GPIO.output(greenPin,high)
    GPIO.output(bluePin,high)

def green():
    GPIO.output(redPin,high)
    GPIO.output(greenPin,low)
    GPIO.output(bluePin,high)
    
def blue():
    GPIO.output(redPin,high)
    GPIO.output(greenPin,high)
    GPIO.output(bluePin,low)
    
def yellow():
    GPIO.output(redPin,low)
    GPIO.output(greenPin,low)
    GPIO.output(bluePin,high)
    
def purple():
    GPIO.output(redPin,low)
    GPIO.output(greenPin,high)
    GPIO.output(bluePin,low)
    
def light_blue():
    GPIO.output(redPin,high)
    GPIO.output(greenPin,low)
    GPIO.output(bluePin,low)
