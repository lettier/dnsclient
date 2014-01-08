'''

David Lettier (C) 2014.

Needs:

	- Bitstring http://pythonhosted.org/bitstring/#download
	- Python 2.7
	
A simple DNS client similar to nslookup. Does not use any DNS libraries. Handles only A type records.

'''

from socket import AF_INET, SOCK_DGRAM # For setting up the UDP socket.
import sys
import socket
import bitstring, struct # For constructing and destructing the DNS packet.

# Construct the DNS packet of header + QNAME + QTYPE + QCLASS.

# Get the host name from the command line.

host_name_to_look_up = "";

try:

	host_name_to_look_up = sys.argv[ 1 ];
	
except IndexError:
	
	print "No host name specified.";
	
	sys.exit( 0 );
	
host_name_to_look_up = host_name_to_look_up.split( "." );

# Begin constructing the DNS packet query.

DNS_QUERY_FORMAT = [ 'hex=id', 'bin=flags', 'uintbe:16=qdcount', 'uintbe:16=ancount', 'uintbe:16=nscount', 'uintbe:16=arcount' ] 

DNS_QUERY = { 
	
	'id': '0x1a2b',
	'flags': '0b0000000100000000', # Standard query. Ask for recursion.
	'qdcount': 1, # One question.
	'ancount': 0,
	'nscount': 0,
	'arcount': 0,	
}

# Construct the QNAME:
# size|label|size|label|size|...|label|0x00

question_hex_string = [];

j = 0;

for i in xrange( 0, len( host_name_to_look_up ) ):
	
	host_name_to_look_up[ i ] = host_name_to_look_up[ i ].strip( );
	
	size = hex( len( host_name_to_look_up[ i ] ) );
	
	if ( len( size ) == 3 ): # Pad a 0 if <= 0xF.

		size = '0x0' + size[ 2 : ];
	
	question_hex_string.append( size );
	
	DNS_QUERY_FORMAT.append( 'hex=' + 'qname' + str( j ) );
	
	DNS_QUERY[ 'qname' + str( j ) ] = question_hex_string[ -1 ];
	
	j += 1;
	
	# Encode the ASCII string as hex.
	
	question_hex_string.append( '0x' + host_name_to_look_up[ i ].encode( 'hex' ) );
	
	DNS_QUERY_FORMAT.append( 'hex=' + 'qname' + str( j ) );
	
	DNS_QUERY[ 'qname' + str( j ) ] = question_hex_string[ -1 ];
	
	j += 1;
	
# Add terminating byte.
	
DNS_QUERY_FORMAT.append( 'hex=qname' + str( j ) );
	
DNS_QUERY[ 'qname' + str( j ) ] = '0x00';

# End QNAME.

# Set the type and class now.
	
DNS_QUERY_FORMAT.append( 'uintbe:16=qtype' );
	
DNS_QUERY[ 'qtype' ] = 1;

DNS_QUERY_FORMAT.append( 'hex=qclass' );
	
DNS_QUERY[ 'qclass' ] = '0x0001';

# Convert the struct to a bit string.

data = bitstring.pack( ','.join( DNS_QUERY_FORMAT ), **DNS_QUERY );

# Send the packet off to the server.

DNS_IP = "8.8.8.8"; # Google DNS server IP.
DNS_PORT = 53; # DNS server port for queries.

READ_BUFFER = 1024; # The size of the buffer to read in the received UDP packet.

address = ( DNS_IP, DNS_PORT ); # Tuple needed by sendto.

client = socket.socket( socket.AF_INET, socket.SOCK_DGRAM ); # Internet, UDP.

client.sendto( data.tobytes( ), address ); # Send the DNS packet to the server using the port.

# Get the response DNS packet back, decode, and print out the IP.

data, address = client.recvfrom( READ_BUFFER ); # Get the response and put it in data. Get the responding server address and put it in address.

# Convert data to bit string.

data = bitstring.BitArray( bytes = data );

# Unpack the receive DNS packet and extract the IP the host name resolved to.

# Get the host name from the QNAME located just past the received header.

host_name = [ ]

# First size of the QNAME labels starts at bit 96 and goes up to bit 104.
# size|label|size|label|size|...|label|0x00

x = 96
y = x + 8

for i in xrange( 0, len( host_name_to_look_up ) ):
	
	# Based on the size of the very next label indicated by 
	# the 1 octet/byte before the label, read in that many 
	# bits past the octet/byte indicating the very next
	# label size.
	
	# Get the label size in hex. Convert to an integer and times it
	# by 8 to get the number of bits.
	
	increment = ( int( str( data[ x : y ].hex ), 16 ) * 8 );
	
	x = y;
	y = x + increment;
	
	# Read in the label, converting to ASCII.
	
	host_name.append( str( data[ x : y  ].hex ).decode( 'hex' ) );
	
	# Set up the next iteration to get the next label size.
	# Assuming here that any label size is no bigger than
	# one byte.
	
	x = y;
	y = x + 8; # Eight bits to a byte.
	
# Get the response code.
# This is located in the received DNS packet header at
# bit 28 ending at bit 32.

response = str( data[ 28 : 32 ].hex );

# Get the record count.

record_count = str( data[ 48 : 64 ].uintbe );

# Check for errors.

if ( response == "1" ):
	
	print "\nFormat error. Unable to interpret query.\n";
	
elif ( response == "2" ):
	
	print "\nServer failure. Unable to process query.\n";
	
elif ( response == "3" ):
	
	print "\nName error. Domain name does not exist.\n";
	
elif ( response == "4" ):
	
	print "\nQuery request type not supported.\n";
	
elif ( response == "3" ):
	
	print "\nServer refused query.\n";

if ( response == "0" ):
	
	# Print the QNAME that was constructed from the received DNS packet.

	print "\nHost Name: " + ".".join( host_name );
	
	# Print the IP the host name resolved to. It is usually the last four octets of the DNS packet. At least for A records.

	print "IP address: " + str( data[ -32 : -24  ].uintbe ) + "." + str( data[ -24 : -16  ].uintbe ) + "." + str( data[ -16 : -8  ].uintbe ) + "." + str( data[ -8 :  ].uintbe ) + "\n";