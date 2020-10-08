# Bluetooth Low Energy (BLE): GATT Reconnaisance /Basic Fuzzer

#### Description
- Reads values from the BLE GATT characteristics
- Basic Fuzzing on the BLE GATT characteristics
**Note:** This fuzzes only Generic Attribute Profile (GATT)

#### Usage
```sh
$ python ble_fuzzer.py <BLE_Peripheral_MAC_Address>
```

#### Pre-requisite
- Bluez has to be installed. Ubuntu comes with Bluez by default. If you are using other flavours of Linux, please install Bluez
- Your computer must support Bluetooth / BLE 

#### Output
- Readable handles can be found in *readable_handles.json*
- Writable handles can be found in *writable_handles.json*
	***Example:*** "0x0c03": [4, 5] in the *writable_handles.json* means we can either write 4 characters or 5 characters to the handle, 0x0c03.
&nbsp;
#### Acknowledgements
- [Bluez](http://www.bluez.org/)
