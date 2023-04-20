#libraries
import RPi.GPIO as GPIO
import time
#disable warnings (optional)
GPIO.setwarnings(False)
#Select GPIO Mode
GPIO.setmode(GPIO.BCM)
#set red,green and blue pins
redPin = 19
greenPin = 13
bluePin = 12
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

turn_off()

# while (1):
#     red()
#     time.sleep(3)
#     green()
#     time.sleep(3)
#     blue()
#     time.sleep(3)
#     turn_off()
#     time.sleep(3)
