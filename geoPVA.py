# Fixed the functions so search works


# GeoPVA v0.1
# Geographic Port Vulnerability Analysis
# jbeer@protonmail.com

########################################## Notes

# Python extensions that may required Installation:
# Pandas            
# IP2location
# ipaddress
# netaddr

# Python Programs Required:
# IP2Location      From the MIT Name the GUY.

########################################## Imports

import re
import csv
import IP2Location
import sys
import os
import string
import socket
import ipaddress
import netaddr
import pandas as P
from pathlib import Path
import operator
from operator import itemgetter

########################################### Welcome Functions 

def FirstWelcome():

    print("")
    print("")
    print("PVGeo v0.1")
    print("Port Vulnerability Geocoding")
    print("")
    print("PVGeo is designed to be used in conjuction with Nmap and GIS software")
    print("to map network port vulerabilities by geographic area.")
    print("This version includes:")
    print("")
    print("- Searching the provided database of Geocodes by Country, City, State, or Zip Code ")
    print("- Creating Whitelist files that can then be used for port scanning on Nmap")
    print("- Searching Nmap log files for open ports and obtaining IP4 Geocoding information")
    print("")
    print("TIPS")
    print("- Created files can be large: Try smaller areas first(zip code)")
    print("- Everything is set to lower case for ease of use")
    print("- Type 'm' at anytime to return to the Main Menu")
    print("- About section contains further information")
    print("- Have fun, and be nice \n\n\n\n")
    
def Welcome():
    
    counter = 0
    fileoutput = ""    
    
    while True:

        print("Search IP geocode search by area:")
        print("")                                       
        print("c for City")
        print("x for Country")
        print("s for State")
        print("z for Zip Code")
        print("----------------------------")
        print("Conversion")
        print("") 
        print("w Make a whitelist file for Nmap") 
        print("n Convert Nmap IP Active Scan to Geographic Equivilent")
        print("p Convert Nmap PORT Scan to Geographic Equivilent")
        print("y Get Percentages")
        print("----------------------------")
        print("Other")
        print("")
        print("i for Instructions")
        print("a for About this Script")
        print("m for Main Menu")
        print("q to Quit\n\n  ")
      
        result = input(":    ")
        if result == "m":
            Welcome()
        result = result.lower()
        
        if result == 'c':
            while True:
                choice1 = input("Is the city/town located in the United States? y/n")                
                
                if choice1 == 'y':
                    A = 5
                    B = 4
                    Text1 = "USA City Name:  "
                    Text2 = "State Name: "
                    Search(counter,fileoutput,A,B,Text1,Text2)
                elif choice1 =='n':
                    A = 5
                    B = 3
                    Text1 = "City Name:  "
                    Text2 = "Country Name:   "
                    Search(counter,fileoutput,A,B,Text1,Text2)
                elif choice1 == 'm':
                    Welcome()            
                else: 
                    Invalid()
                    True
        
        elif result == 's' :
            A = 0
            B = 4
            Text1 = "State Name"
            Text2 = ""
            Search(counter,fileoutput,A,B,Text1,Text2)
            
        elif result == 'z' :
            A = 0
            B = 8
            Text1 = '\nZip Code'
            Text2 = " "
            GetResults(counter,fileoutput,A,B,Text1,Text2)

        elif result == 'x' :
            A = 4
            B = 0
            Text1 = '\nCountry\n'
            Text2 = " "
            GetResults(counter,fileoutput,A,B,Text1,Text2)

        elif result == 'w' :
            Whitelist()

        elif result == 'n' :
           ipScanConvert()

        elif result == 'p' :                    
            PortScanConvert()

        elif result =='y':
            GetPercent()

        elif result == 'i' :
            Instructions()
            Welcome()
            
        elif result == 'a' :
            About()
            Welcome()
            
        elif result == 'q' :
            print('\nBYE!')
            break
        else:
            print('\n Invalid Input, Please try again \n')
            
########################################### Other Functions 

def Completed():
    
    print (" ")                 
    print('COMPLETED! \n')
    print (" ")

def Invalid():
    
    print(" ")
    print ("Invalid. Type y for Yes n for No")
    print (" ")

def Instructions():     #i
    
    print("\n\n")
    print("1. Search IP geocode search by area")
    print("2. Create a CIDR/whitelist file for nmap scanning ")
    print("3. Use the created whitelist file on Nmap to check if the IP addresses are active")
    print("4. Use the created whitelist file on Nmap to Port Scan")
    print("5. Convert your Nmap scan of active IP addresses to geographic equivilent ‘n’")
    print("6. Convert your Nmap port to a geographic equivilent ‘n’")
    print("7. Run ‘Get Percentages’ to see the percentage of vulnerability by area and create GIS importable files ‘y’")
    print("\n\n\n\n")

def About():          #a
    
    print("For more Information about me please visit my website at: ")
    print("Thanks to Mohammed Ismail for help and motivation on this Project")
    print("- Jonathan ")
    
########################################## Geocodes by area searches


def Search(counter,fileoutput,A,B,Text1,Text2):         
    
    def Overall(area):                  #General Function for one Variable: Country or State
        area = area.lower()
        counter = 0
        fileoutput = input("Please name your file:     ")
        if fileoutput == "m":
            Welcome()
        
        with open('IP2LOCATION-LITE-DB11.CSV','r') as f:
            with open(fileoutput,'w') as FF: 
                for line in f:
                     a = line.split(',',A)[A]
                     a = a.split(",")[B]
                     a = a.lower()
                     if area in a:
                         FF.write(line)
                         print(line)
                         
                         counter += 1
        Results(counter,fileoutput)
        
    def Overall2(area,area2):           #Function for two variables: Cities
        counter = 0
        area = area.lower()
        area2 = area2.lower()
        fileoutput = input("\nPlease name your file:     ")
        if fileoutput == "m":
            Welcome()
        with open('IP2LOCATION-LITE-DB11.CSV','r') as f:
            with open(fileoutput,'w') as FF: 
                for line in f:
                    
                    a = line.split(',',A)[A]
                    a = a.split(",")[0]
                    a = a.lower()
                    
                    b = line.split(',',B)[B]
                    b = b.split(",")[0]
                    b = b.lower()
                    
                    if area2 in a and area in b:
                        
                        FF.write(line)
                        print(line)
                        
                        counter += 1
        Results(counter,fileoutput)
            
    if "Zip" in Text1:                #ZipCode in the USA     Had to make a third function for Zip Codes. The "United States" section could be shortened
        counter = 0

        area = input("What Zip Code:     ")
        if area == "m":
            Welcome()

        fileoutput = input("\nPlease name your file:     ")
        if fileoutput == "m":
            Welcome()

        with open('IP2LOCATION-LITE-DB11.CSV','r') as f:
            with open(fileoutput,'w') as FF: 
                for line in f:
                    if "United States" in line:
                     a = line.split(',',A)[A]
                     a = a.split(",")[B]
                     a = a.capitalize()
                     
                     if area in a:
                         FF.write(line)
                         print(line)
                         counter += 1

        Results(counter,fileoutput)
        
    elif "USA" in Text1:                #City IN the USA

        area = input("\nWhich State:")
        if area == "m":
            Welcome()
    
        area2 = input("\nWhich City:")
        if area2 == "m":
            Welcome()

        Overall2(area,area2)
                
    elif "Country" in Text2:            #City outside of the USA
            area = input("\nWhich Country:")
            area2 = input("\nWhich City:")
            if area == "m":
                Welcome()
            Overall2(area,area2)
                             
    elif "State" in Text1:              #Entire State
        area = input("\nWhich State: ")
        if area == "m":
            Welcome()
        Overall(area)
        
    elif "Country" in Text1:            #Entire Country
        area = input("\nWhich Country: ")
        if area == "m":
            Welcome()
        Overall(area)
   
    else:
        Welcome()
        
######################################### c Geocoding Search Results  

def Results(counter,fileoutput):
    
    if counter == 0:
        print ("")                                  
        print("Nothing Found \nFile Not Created")  
        print (" ")
        os.remove(fileoutput)
        Welcome()
    else:
        Completed()
        countMult = counter * 256
        print(counter, " lines found ")
        print(countMult," Possible Individual IP addresses to scan.")
        print (" ")
        Welcome()
########################################## w Create a whitelist file for Nmap: converts to CIDR Notation 

def Whitelist():      
        
    while True:
        file = input("what file to get from:     ")
        if file == "m":
            Welcome()
        if os.path.exists(file):
            break
        else:
            print("\n")
            print("File doesn't exist\nPress m for the Main Menu or Try Again")
            print("\n")
            True

    output = input("name the output file:     ")
    if file == "m":
        Welcome()
        
    with open(file,'r') as f:        
        with open('A.txt','w') as FF:    
            for line in f:
                line = line[:25].replace (",","").replace ('"',' ')
                line = re.sub("[^0-9]", " ", line)

                FF.write(line[:25])                
                FF.write("\n")

    with open('A.txt','r') as AA:
        with open('B.txt','w') as BB:        
            
            UniqueLines = set()
            IPraw = []
           
            for line in AA:
                line = line.split() 
                
                if line:            
                    line = [int(i) for i in line]
                    IPraw.append(line)
                    for thing in IPraw:
                        thing = [ipaddress.IPv4Address(item).__str__() for item in thing]
                        cidrs = netaddr.iprange_to_cidrs(thing[0],thing[1])
                    outfile = open(output, "w")  
                    for item in cidrs:
                        item = str(item)
                        if item not in UniqueLines:
                            
                            print(item)
                            UniqueLines.add(item)
                            BB.write(item)
                            BB.write("\n")
                
        os.rename('B.txt',output)         #this was necessary: crashed when used input directly
        os.remove('A.txt')
        AA.close()
        BB.close()

        Completed()
        Welcome()

########################################## This function creates Geographic output of Nmap active IP AND Port Scans      

def Convert2Geo(FileOut):                      

    FileExt = '.txt'
    FileGG = 'GG'
    
    FileStripped = FileOut.strip(".txt")

    FileOut2 = FileStripped + FileGG + FileExt
    
    with open(FileOut2,'w')as filename:
        with open (FileOut, 'r') as FF:
            
            database = IP2Location.IP2Location(os.path.join("data", "IP-COUNTRY.BIN"))

            FF = [x.strip() for x in FF]
            filename.write('IP CC Country RegionOrState City lat long AreaCode \n')


            for ff in FF:

                try:            
                    rec = database.get_all(ff)

                    lat = rec.latitude
                    lat = str(lat)
                    long = rec.longitude
                    long = str(long)

                    filename.write(rec.country_short.decode('utf-8'))
                    filename.write(' ')
                    filename.write(rec.country_long.decode('utf-8').replace(" ", ""))
                    filename.write(' ')
                    filename.write(rec.region.decode('utf-8').replace(" ", ""))
                    filename.write(' ')
                    filename.write(rec.city.decode('utf-8').replace(" ", ""))
                    filename.write(' ')
                    filename.write(lat)
                    filename.write(' ')
                    filename.write(long)
                    filename.write(' ')
                    filename.write(rec.zipcode.decode('utf-8'))
                    filename.write('\n')
                    print(rec.country_short.decode('utf-8'),rec.country_long.decode('utf-8').replace(" ", ""),rec.region.decode('utf-8').replace(" ", ""),rec.city.decode('utf-8').replace(" ", ""),lat,long,rec.zipcode.decode('utf-8'))

                except:
                    pass

    Completed()         
    Welcome()        

######################################### p   Finds Nmap Port hits and converts them to geographic output through Convert2Geo

def PortScanConvert():

    while True:
        FileStart = input("What is the name of the Nmap Port scan file")

        if FileStart == "m":
            Welcome()
        if os.path.exists(FileStart):
            break
        else:
            print("\n")
            print("File doesn't exist\nPress m for the Main Menu or Try Again")
            print("\n")
            True

    FileExt = '.txt'
    FileStartStrip = FileStart.strip('.txt')

    while True:
         
        try:
            WhatPort = int(input("What specific port are you looking for? (give a number)  :  "))
            if WhatPort == "m":
                Welcome()
        except ValueError:
            print("This is not a whole number.")
            continue
        else:
            break
        
    WhatPort = str(WhatPort)
    FileOut = FileStartStrip + WhatPort + FileExt 
    file = open(FileStart, 'r')
    PortOpen = WhatPort + '/open'
    
    with open(FileOut, 'w') as FileOutWrite:
        
        for line in file:
                
            if PortOpen in line:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line, flags=0)
                a = ip[0]
                FileOutWrite.write(a)
                FileOutWrite.write('\n')
    
    Convert2Geo(FileOut)    

######################################### n Converts Nmap IP active scan to geographic output through Convert2Geo
def ipScanConvert():

    while True:
        
        fileIN = input("What is the name of your file:   ")
        str(fileIN)
        
        if fileIN == "m":
            Welcome()
        if os.path.exists(fileIN):
            break
        else:
            print("\n")
            print("File doesn't exist\nMake sure .txt is NOT added here\nPress m for the Main Menu or Try Again")
            print("\n")
            True
    FileExt = '.txt'
    FileStripped = fileIN.strip('.txt')
    FileNhits = "Nhits"
    FileOut = FileStripped + FileNhits + FileExt

    with open(fileIN, 'r') as file:
        with open (FileOut,'w') as FileOutWrite:
            for line in file:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
                FileOutWrite.write(''.join(map(str, ip)))
                FileOutWrite.write('\n')
    
    Convert2Geo(FileOut)

########################################## y Compares two files and gets percentages of port hits by area

def GetPercent():    

    while True:        
        FileIP = input("First Give me your scan of all active IP's:  ")
        if FileIP == "m":
            Welcome()
        if os.path.exists(FileIP):
            break
        else:
            print("\n")
            print("File doesn't exist\nPress m for the Main Menu or Try Again")
            print("\n")
            True

    while True:
        FileHits = input("Now Give me your file of Nmap Port Hits:   ")
        if FileHits == "m":
            Welcome()
        if os.path.exists(FileHits):
            break
        else:
            print("\n")
            print("File doesn't exist\nPress m for the Main Menu or Try Again")
            print("\n")
            True

    FinalFile = input("Please name your final output file(No extension please):   ")
    if FinalFile == "m":
        Welcome()
    
    FileExt = '.csv'

    Country = FinalFile + "Country" + FileExt
    City = FinalFile + "City" + FileExt
    Region = FinalFile + "Region" + FileExt
    AreaCode = FinalFile + "ZipCode" + FileExt       #The database calls Zip Codes 'area codes' 
        
    Nhits = P.read_csv(FileIP, delim_whitespace=True,names=['IP', 'CC', 'Country', 'RegionOrState', 'City', 'lat', 'long' ,'AreaCode'], low_memory=False)

    CountryIPhits = Nhits.groupby('Country').Country.count().to_dict() 
    StateIPhits = Nhits.groupby('RegionOrState').RegionOrState.count().to_dict()
    CityIPhits = Nhits.groupby('City').City.count().to_dict()  
    ZipIPhits = Nhits.groupby('AreaCode').AreaCode.count().to_dict() 

    Znames = ['IP', 'CC', 'Country', 'RegionOrState', 'City', 'lat', 'long' ,'AreaCode']

    Zhits = P.read_csv(FileHits, delim_whitespace=True, names=['IP', 'CC', 'Country', 'RegionOrState', 'City', 'lat', 'long' ,'AreaCode'],low_memory=False)

    CountryPortHits = Zhits.groupby('Country').Country.count().to_dict() 
    CityPortHits = Zhits.groupby('City').City.count().to_dict()  
    StatePortHits = Zhits.groupby('RegionOrState').RegionOrState.count().to_dict()
    ZipPortHits = Zhits.groupby('AreaCode').AreaCode.count().to_dict() 
                    
    CountrySort = {k: CountryPortHits[k]/CountryIPhits[k] for k in CountryIPhits.keys() & CountryPortHits}
    StateSort = {k: StatePortHits[k]/StateIPhits[k] for k in StateIPhits.keys() & StatePortHits}
    CitySort = {k: CityPortHits[k]/CityIPhits[k] for k in CityIPhits.keys() & CityPortHits}
    ZipSort = {k: ZipPortHits[k]/ZipIPhits[k] for k in ZipIPhits.keys() & ZipPortHits}

    CountryPercent = sorted(CountrySort.items(), key=itemgetter(1))
    StatePercent = sorted(StateSort.items(), key=itemgetter(1))
    CityPercent = sorted(CitySort.items(), key=itemgetter(1))
    ZipPercent = sorted(ZipSort.items(), key=itemgetter(1))
    
    CountryPort = sorted(CountryPortHits.items(), key=itemgetter(1))
    CountryIP = sorted(CountryIPhits.items(), key=itemgetter(1))
    StatePort = sorted(StatePortHits.items(), key=itemgetter(1))
    StateIP = sorted(StateIPhits.items(), key=itemgetter(1))
    CityPort = sorted(CityPortHits.items(), key=itemgetter(1))
    CityIP= sorted(CityIPhits.items(), key=itemgetter(1))
    ZipPort = sorted(ZipPortHits.items(), key=itemgetter(1))
    ZipIP = sorted(ZipIPhits.items(), key=itemgetter(1))

    with open(Country, 'w') as f:
        [f.write('{0},{1}\n'.format(key, value)) for key, value in CountrySort.items()]
        f.close()

    with open(City, 'w') as f:
        [f.write('{0},{1}\n'.format(key, value)) for key, value in CitySort.items()]
        f.close()

    with open(Region, 'w') as f:
        [f.write('{0},{1}\n'.format(key, value)) for key, value in StateSort.items()]
        f.close()

    with open(AreaCode, 'w') as f:
        [f.write('{0},{1}\n'.format(key, value)) for key, value in ZipSort.items()]
        f.close()
      
    print("\n\nNMAP IP COUNTRY HITS\n")
    for key, value in CountryIP:
        print (key,'\t',value)

    print("\nNMAP PORT COUNTRY HITS\n")
    for key, value in CountryPort:
        print (key,'\t',value)

    print("\nNMAP IP STATE HITS\n")    
    for key, value in StateIP:
        print (key," "*(20-len(key)),value)

    print("\nNMAP PORT STATE HITS\n")
    for key, value in StatePort:
        print (key," "*(20-len(key)),value)

    print("\nNMAP IP CITY HITS\n")
    for key, value in CityIP:
        print (key," "*(20-len(key)),value)

    print("\nNMAP PORT CITY HITS\n")   
    for key, value in CityPort:
        print (key," "*(20-len(key)),value)

    print("\nNMAP IP ZIP CODE HITS\n")   
    for key, value in ZipIP:
        print (key," "*(20-len(key)),value)

    print("\nNMAP PORT ZIP CODE HITS\n")   
    for key, value in ZipPort:
        print (key," "*(20-len(key)),value)

    print("\nCOUNTRY PERCENTAGES\n")
    for key, value in CountryPercent:
        print (key,'\t',value)
            
    print("\nSTATE PERCENTAGES\n")
    for key, value in StatePercent:
        print (key,'\t',value)

    print("\nCITY PERCENTAGES\n")
    for key, value in CityPercent:
        print(key," "*(20-len(key)),value)
    
    print("\nZIP CODE PERCENTAGES\n")    
    for key, value in ZipPercent:
        print (key,'\t',value)
        
    Completed()
    Welcome()
    
###############################################    Starts the Program

FirstWelcome()
Welcome()

###############################################     Notes: Fixes and Possible Add-ons

##Stuff to add NOW:

## Explanation of every Function
## Double Check input Statements text
## GIS importation Explanation
## Explanation of Size and database
## Clean up Functions
## Format for Percentages
## GetPercentages Sorting Options
## Which Country Add
## Using two databases, why? Switch to one if possible

## Ideas for later:

## GUI
## One Process for all: File processing stage and Geographic output Stage
## nmap Intergration
## GIS intergration
