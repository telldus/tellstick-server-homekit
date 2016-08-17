# -*- coding: utf-8 -*-

tlv_types = {
	'auth_method': 0x00,     # kTLVType_Method
	'identifier': 0x01,      # kTLVType_Identifier
	'salt': 0x02,            # kTLVType_Salt
	'public_key': 0x03,      # kTLVType_PublicKey
	'proof': 0x04,           # kTLVType_Proof
	'encrypted_data': 0x05,  # kTLVType_EncryptedData
	'state': 0x06,           # kTLVType_State
	'error': 0x07,           # kTLVType_Error
	'read_delay': 0x08,      # kTLVType_ReadDelay
	'certificate': 0x09,     # kTLVType_Certificate
	'signature': 0x0a,       # kTLVType_Signature
	'permissions': 0x0b,     # kTLVType_Permissions
	'fragment_data': 0x0c,   # kTLVType_FragmentData
	'separator': 0xFF        # kTLVType_Separator
}

tlv_status = {
	'ok': 0x00,
	'unknown': 0x01,
	'auth': 0x02,
	'toomanyattempts': 0x03,
	'unknownpeer': 0x04,
	'maxpeers': 0x05,
	'maxtries': 0x06,
}

def get_tlv_name(type_id):
	return list(tlv_types)[tlv_types.values().index(type_id)]

def get_tlv_id(type_name):
	return tlv_types[type_name]

def pack(input):
	output = []
	for package in input:
		if package['length'] == 0:  # Used by separator
			output += [chr(get_tlv_id(package['type']))]
			output += [chr(0)]
			continue
		while package['length'] > 0:
			if package['length'] == 1 and not isinstance(package['data'], list):
				package['data'] = [package['data']]
			output += [chr(get_tlv_id(package['type']))]
			if package['length'] > 255:
				output += [chr(255)]
				package['length'] -= 255
			else:
				output += [chr(package['length'])]
				package['length'] = 0
			output += package['data'][0:255]
			package['data'] = package['data'][255:]
	output = bytearray(output)
	return str(output)

def unpack(input):
	input = bytearray(input)
	mark = 0
	output = []
	output_hash = {}
	while(mark < len(input)):
		p_type = get_tlv_name(input[mark])
		mark += 1
		p_len = input[mark]
		mark += 1
		p_data = list(input[mark:mark+p_len])
		mark += p_len
		if len(output) and p_type == output[-1]['type'] and output[-1]['length'] >= 255:
			output[-1]['length'] += p_len
			output[-1]['data'] += p_data
			output_hash[p_type] = {'length': output[-1]['length'], 'data': output[-1]['data']}
		else:
			package = {'type': p_type, 'length': p_len, 'data': p_data}
			output.append(package)
			output_hash[p_type] = {'length': p_len, 'data': p_data}

	return output_hash
