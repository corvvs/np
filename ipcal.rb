require 'json'

def int2dot(integer)
	(0...4).map{ 
		(integer % 256).tap{ integer /= 256 }
	}.reverse.join(".")
end

def dot2int(dot)
	m = dot.match(/^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?\s*$/)
	return nil if !m
	array = [m[1], m[2], m[3], m[4]].map(&:to_i)
	return nil unless array.all?{ |v| 0 <= v && v <= 255 }
	integer = array.reduce(0){ |s,i| (s << 8) + i }
end

def parse_subnetmask(str)
	addr = parse_dot(str, false)
	if addr

	end
end

# IPアドレスクラス
AddressClass = [
	{
		class: "A",
		address_max: dot2int("127.255.255.255"),
	},
	{
		class: "B",
		address_max: dot2int("191.255.255.255"),
	},
	{
		class: "C",
		address_max: dot2int("223.255.255.255"),
	},
	{
		class: "D",
		address_max: dot2int("239.255.255.255"),
	},
	{
		class: "E",
		address_max: dot2int("255.255.255.255"),
	},
]
# プライベートアドレスレンジ
PrivateAddress = {
	"A": "10.0.0.0/8",
	"B": "172.16.0.0/12",
	"C": "192.168.0.0/16",
}

def parse_mask(mask)
	case
	when mask.match(/^\d+$/) && 0 <= mask.to_i(10) && mask.to_i(10) <= 32
		return mask
	when mask.match(/^\d+\.\d+\.\d+\.\d+$/)
		addrs = mask.split(".").map{ |s| s.to_i(10) }
		if addrs.all?{ |a| 0 <= a && a <= 255 }
			binstr = sprintf("%08b%08b%08b%08b", *addrs)
			m = binstr.match(/^(1*)(0*)$/)
			if m
				return "#{m[1].length}"
			end
		end
	end
	$stderr.puts "invalid mask format: #{mask}"
	nil
end

def parse_dot(dot, pv = true)
	m = dot.match(/^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(.+))?\s*$/)
	return nil if !m
	mask = m[5] ? parse_mask(m[5]) : nil
	return nil if m[5] && !mask
	array = [m[1], m[2], m[3], m[4]].map(&:to_i)
	return nil unless array.all?{ |v| 0 <= v && v <= 255 }
	integer = array.reduce(0){ |s,i| (s << 8) + i }
	address_class = AddressClass.find{ |d| integer <= d[:address_max] }
	binstr = sprintf("%032b", integer);
	binquad = binstr.scan(/\d{8}/)
	r = {
		dot: dot,
		array: array,
		integer: integer,
		hex: sprintf("%08x", integer),
		bin: sprintf("%032b", integer),
		binquad: binquad.join(" "),
		address_class: address_class ? address_class[:class] : nil,
	};
	# netmask
	if mask
		cidr = mask.to_i(10)
		unless 0 <= cidr && cidr <= 32
			return nil
		end
		netmask = (1 << 32) - (1 << (32 - cidr))
		r[:cidr] = cidr
		r[:netmask_int] = netmask
		r[:netmask_hex] = sprintf("%08x", netmask)
		r[:netmask_bin] = sprintf("%032b", netmask)
		r[:netmask_binquad] = r[:netmask_bin].scan(/\d{8}/).join(" ")
		r[:netmask] = int2dot(netmask)
		network_int = integer & netmask
		r[:network_int] = network_int
		r[:network_dot] = int2dot(network_int)
		r[:network] = r[:network_dot]
		broadcast = network_int | ((1 << (32 - cidr)) - 1)
		r[:broadcast_dot] = int2dot(broadcast)
		if cidr < 31
			r[:first_host_dot] = int2dot(network_int + 1)
			r[:last_host_dot] = int2dot(broadcast - 1)
		end
		if cidr < 32
			r[:host_num] = broadcast - network_int - 1
		end
	end
	# like a mask?
	if m = r[:bin].match(/^(1*)0*$/)
		r[:is_like_a_mask] = true
		r[:as_cidr] = m[1].size
		r[:as_first_host_dot] = int2dot(integer + 1)
		r[:as_last_host_dot] = int2dot((1 << 32) - 2)
	end
	# check private address
	if pv
		PrivateAddress.each{ |klass, pa|
			a = parse_dot(pa, false)
			if a[:integer] == (integer & a[:netmask_int])
				r[:is_private] = klass
			end
		}
	end
	# check loopback
	r[:is_loopback] = integer == dot2int("127.0.0.1")
	return r
end

str = ARGV[0].chomp.gsub(/\s/, "")

case
when parsed = parse_dot(str)
	puts JSON.pretty_unparse(parsed)
else
	puts "Invalid Arg: #{str}";
end