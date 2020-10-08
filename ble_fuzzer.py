import itertools
import sys
import subprocess
import time
import shlex
import json
import re

class blefuzzer:
	def read_input(self):
			if len(sys.argv) != 2:
			    print ('Usage: sudo python ble_fuzzer.py <BLE_Device MAC_Address>')
			    print ('Example: sudo python ble_fuzzer.py XX:XX:XX:XX:XX:XX')
			    sys.exit(1)

			print ('Hint: More the characters more the execution time')
			
			try:
				self.chars_to_write = input("How many characters(maximum) you would like to write to GATT handle?: ")
			except:
				print('Please enter valid number!')
				sys.exit(1)
			
			print ('Hint: If BLE peripheral is not accepting connections with default <public> LE Address type, input <random>')
			self.le_address_type = raw_input("Set LE address type (public/ random): ")
			self.mac_address = sys.argv[1]


	def read_handle(self):	# Fuzz all handles to identify valid ones; Read GATT Characteristics from valid handles
		try:
			counter = 0
			readable_handle = {}	#Dictionary to hold valid handles
			# Reset Host controller Interface (HCI)
			hci_interface = 'hciconfig hci0 down' 
			hci_call = subprocess.call(hci_interface, shell=True)
			hci_interface = 'hciconfig hci0 up' 
			hci_call = subprocess.call(hci_interface, shell=True)
			# print Primary services offered by BLE device/peripheral
			print ('BLE Primary Services: ')
			ble_primary_service = 'gatttool --addr-type=%s --primary --device=%s' %(self.le_address_type,self.mac_address)
			hci_call = subprocess.call(ble_primary_service, shell=True)
			print('\n\n')
			print ('Starting to read characteristics... ')

			# Possible values for Characteristic Handle: Between 0x0000 and 0xffff
			char_handle_all_combinations = [0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f']
			for each_combination in itertools.product(char_handle_all_combinations, char_handle_all_combinations, char_handle_all_combinations, char_handle_all_combinations):
				characteristic_handle = '0x'
				for item in each_combination:
					characteristic_handle+=str(item)

				characteristic_handle = characteristic_handle.strip()
				print (characteristic_handle,':')
				characteristic_read = 'gatttool --addr-type=%s --device=%s --char-read --handle=%s' %(self.le_address_type, self.mac_address, characteristic_handle)
				
				while True:	#Try until succesful connection is made to read a characteristics from BLE device
					process = subprocess.Popen(shlex.split(characteristic_read), stdout=subprocess.PIPE)
					stdout = process.communicate()
					exit_code = process.poll()	#exit code of the process. '0'-if all good; '1'-if something is bad; 'None'- if the process is still executing 

					if stdout[0] == '' and exit_code == 0:
						print ('Invalid Handle')

					if stdout[0] == '' and exit_code == 1:
						print ('Oops! Connection Refused /No route to host')
						continue

					if stdout[0] != '' and exit_code == 0:
						characeteristic = stdout[0].strip('\n')
						print (characeteristic)
						# To get rid off unwanted handle/characteristic values
						regex = re.search('^Characteristic value\/descriptor:[\s]+(.*)', characeteristic)
						clean_charecteristic = regex.groups()[0]
						readable_handle[characteristic_handle] = clean_charecteristic	#Pushing readable handles to dictionary

					counter+=1
					# Let me sleep for a while as peripheral response becomes instable at times due to continous requests. Sleeps after every 100 iterations /GATT Characteristics read
					if counter%100 == 0:
						time.sleep(0)			
					break

			#Lets dump the readable_handles for later inspection
			with open ('readable_handles.json', 'w+') as json_descriptor:
				json.dump(readable_handle,json_descriptor)


		except Exception as e:
			print (e)
			return None

		

	def write_handle(self):
		handle_writable_chars = {}	#Holds writable character length for each handle
		print ('Writing values to the characeteristic handle')
		# Possible values for Characteristic Handle: Between 0x0000 and 0xffff
		char_handle_all_combinations = [0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f']
		for each_combination in itertools.product(char_handle_all_combinations, char_handle_all_combinations, char_handle_all_combinations, char_handle_all_combinations):
			characteristic_handle = '0x'
			for item in each_combination:
				characteristic_handle+=str(item)

			characteristic_handle = characteristic_handle.strip()
			handle_values = []
			value = ''
			for char_value_length in range(self.chars_to_write):
				value+= str(0)
				cmd = 'gatttool --addr-type=%s --device=%s --char-write-req --handle=%s --value=%s' %(self.le_address_type,self.mac_address,characteristic_handle,value)
				
				while True:
					try:
						process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE) 
						stdout = process.communicate()
						exit_code = process.poll()	#exit code of the process. '0'-if all good; '1'-if something is bad; 'None'- if the process is still executing
						print (characteristic_handle,':')
						print 'Trying to write %s characters:' %(char_value_length+1)
						if stdout[0] != '' and exit_code == 0:
							print stdout[0]
							print 'Written %s chars' %(char_value_length+1)
							handle_values_list = handle_values.append(char_value_length+1)
							break

						if stdout[0] == '' and exit_code == 0:
							break

						if stdout[0] == '' and exit_code == 1:
							print 'Oops! Unable to reach host. I am trying again...'
							continue

					except Exception as e:
						print 'Seems I am having issues reaching BLE Device. Will try again...', e
						continue

			handle_writable_chars[characteristic_handle] = handle_values
				

			#Lets dump the dictionary(handle_writable_chars) to an external file(writable_handles). This file holds all the valid handles
			with open ('writable_handles.json', 'w+') as json_descriptor:
				json.dump(handle_writable_chars,json_descriptor)

		else:
			print 'Oops! There are no GATT handles to write'
 


class ble_fuzzer_quick:
	def read_input(self):
		if len(sys.argv) != 2:
		    print 'Usage: sudo python ble_fuzzer.py <BLE_Device MAC_Address>'
		    print 'Example: sudo python ble_fuzzer.py XX:XX:XX:XX:XX:XX'
		    sys.exit(1)

		print 'Hint: More the characters more the execution time'
		
		try:
			self.chars_to_write = input("How many characters(maximum) you would like to write to GATT handle?: ")	
		except:
			print'Please enter valid number!'
			sys.exit(1)
		
		print 'Hint: If BLE peripheral is not accepting connections with default <public> LE Address type, input <random>'
		self.le_address_type = raw_input("Set LE address type (public/ random): ")
		self.mac_address = sys.argv[1]


	def read_handle(self):	# Fuzz all handles to identify valid ones; Read GATT Characteristics from valid handles	
		try:
			counter = 0
			readable_handle = {}	#Dictionary to hold valid handles
			# Bring Host controller Interface (HCI) up
			hci_interface = 'hciconfig hci0 down' 
			hci_call = subprocess.call(hci_interface, shell=True)
			hci_interface = 'hciconfig hci0 up' 
			hci_call = subprocess.call(hci_interface, shell=True)
			# print Primary services offered by BLE device/peripheral
			print 'BLE Primary Services: '
			ble_primary_service = 'gatttool --addr-type=%s --primary -b %s' %(self.le_address_type, self.mac_address)
			process = subprocess.Popen(shlex.split(ble_primary_service), stdout=subprocess.PIPE) 
			stdout = process.communicate()
			exit_code = process.poll()	#exit code of the process. '0'-if all good; '1'-if something is bad; 'None'- if the process is still executing 
			print stdout[0]
			primary_services = re.findall("0x[0-9a-f]+", stdout[0])
			length = len(primary_services)
			group1 = primary_services[0:length:2]	#Picks alternative values in a list starting from first
			group2 = primary_services[1:length:2]	#Picks alternative values in a list starting from second
			self.group1 = group1
			self.group2= group2
			print'\n'
			print 'Starting to read characteristics... \n'

			for handle_from_group1,handle_from_group2 in zip(group1,group2):	# Picks handle (same index) from group1 and group2
				handle_from_group1 = int(handle_from_group1, 16)				# Converts string handle to decimal handle
				handle_from_group2 = int(handle_from_group2, 16)
				for handle in range(handle_from_group1, handle_from_group2+1):	# Iterates through all handles in the range. ex: 0001-000f
					current_handle = '0x%04x' % handle
					print '%s: ' %current_handle
					characteristic_read = 'gatttool --addr-type=%s --device=%s --char-read --handle=%s' %(self.le_address_type, self.mac_address, current_handle)
					while True:	#Try until succesful connection is made to read a characteristics from BLE device
						process = subprocess.Popen(shlex.split(characteristic_read), stdout=subprocess.PIPE) 
						stdout = process.communicate()
						exit_code = process.poll()	#exit code of the process. '0'-if all good; '1'-if something is bad; 'None'- if the process is still executing 

						if stdout[0] == '' and exit_code == 0:
							print 'Invalid Handle'

						if stdout[0] == '' and exit_code == 1:
							print 'Oops! Connection Refused /No route to host'
							continue

						if stdout[0] != '' and exit_code == 0:
							characeteristic = stdout[0].strip('\n')
							regex = re.search('^Characteristic value\/descriptor:[\s]+(.*)', characeteristic)	# To get rid off unwanted handle/characteristic values
							clean_charecteristic = regex.groups()[0]
							# clean_charecteristic = clean_charecteristic.replace(' ','')
							# clean_charecteristic =clean_charecteristic.decode('hex')	#Convert hex string to ascii
							print clean_charecteristic									#Disable this line if you dont want the output to be displayed on screen
							readable_handle[current_handle] = clean_charecteristic		#Pushing readable handles to dictionary

						counter+=1
						# Let me sleep for a while. Sleeps after every 100 iterations /GATT Characteristics read
						if counter%100 == 0:
							time.sleep(0)			
						break
					print '\n'
			
			#Lets dump the readable_handles for later inspection
			with open ('readable_handles.json', 'w+') as json_descriptor:
				json.dump(readable_handle,json_descriptor)

			print 'I am done with reading GATT Characteristics. It is time to write  GATT Characteristics\n'
			

		except Exception as e:
			print e
			return None


	def write_handle(self):
		readable_handle = self.read_handle()
		handle_writable_chars = {}	#Holds writable character length for each handle
		for handle_from_group1,handle_from_group2 in zip(self.group1, self.group2):	# Picks handle (same index) from group1 and group2
			handle_from_group1 = int(handle_from_group1, 16)						# Converts string handle to decimal handle
			handle_from_group2 = int(handle_from_group2, 16)
			for handle in range(handle_from_group1, handle_from_group2+1):			# Iterates through all handles in the range. ex: 0001-000f
				current_handle = '0x%04x' % handle
				print "***************************************************************************************************"
				print '%s: ' %current_handle
				handle_values = []
				value = ''
				for char_value_length in range(self.chars_to_write):
					value+= str(0)
					cmd = 'gatttool --addr-type=%s --device=%s --char-write-req --handle=%s --value=%s' %(self.le_address_type,self.mac_address,current_handle,value)
					
					while True:
						try:
							process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE) 
							stdout = process.communicate()
							exit_code = process.poll()	#exit code of the process. '0'-if all good; '1'-if something is bad; 'None'- if the process is still executing
							print 'Trying to write %s characters:' %(char_value_length+1)
							if stdout[0] != '' and exit_code == 0:
								print stdout[0]
								print 'Written %s chars' %(char_value_length+1)
								handle_values_list = handle_values.append(char_value_length+1)
								break

							if stdout[0] == '' and exit_code == 0:
								break

							if stdout[0] == '' and exit_code == 1:
								print 'Oops! Unable to reach host. I am trying again...'
								continue

						except Exception as e:
							print 'Seems I am having issues reaching BLE Device. Will try again...', e
							continue

				handle_writable_chars[current_handle] = handle_values
				print handle_writable_chars


		#Lets dump the dictionary(handle_writable_chars) to an external file(writable_handles). This file holds all the valid handles
		with open ('writable_handles.json', 'w+') as json_descriptor:
			json.dump(handle_writable_chars,json_descriptor)


if __name__ == '__main__':
	print ("""
                      
      ======    ||        ======
      ||    |   ||        ||
      ||    |   ||        ||
       =====    ||         ====
      ||    |   ||        ||
      ||    |   ||        ||          
      ======    =======   ======      Recon /Fuzzer  
      """)
	
	print ("By default this script fuzzes only handles associated with GATT primary services\n")
	fuzz_type = raw_input("Do you wish to fuzz all the GATT handles(65536) or only handles specific to GATT primary services? Fuzzing all GATT handles takes ages. Type 'y' if yes: ")
	if fuzz_type == 'y' or fuzz_type == 'Y':
		fuzz = blefuzzer()
		read_inputs = fuzz.read_input()
		attribute_type = raw_input ("Do you wish to read values from all the GATT handles before writing values to it? If yes, type 'y': ")
		if attribute_type == 'y' or attribute_type == 'Y':
			read_handles = fuzz.read_handle()
			write_handles = fuzz.write_handle()
			sys.exit(0)

		else:
			write_handles = fuzz.write_handle()
			sys.exit(0)

	else:
		fuzz = ble_fuzzer_quick()
		read_inputs = fuzz.read_input()
		write_handles = fuzz.write_handle()

	