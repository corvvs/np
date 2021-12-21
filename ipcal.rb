require 'json'


# 単一整数表記 -> ドット区切り表記
def unit2dot(unit)
	(0...4).map{ 
		(unit % 256).tap{ unit /= 256 }
	}.reverse.join(".")
end

# ドット区切り表記 -> 単一整数表記
def dot2unit(dot)
	m = dot.match(/^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?\s*$/)
	return nil if !m
	array = [m[1], m[2], m[3], m[4]].map(&:to_i)
	return nil unless array.all?{ |v| 0 <= v && v <= 255 }
	integer = array.reduce(0){ |s,i| (s << 8) + i }
end

# 単一整数表記 -> 2進数表記
def unit2binary(unit)
	sprintf("%032b", unit)
end

# 2進数表記 -> 単一整数表記
def binary2unit(binary)
	binary.to_i(2)
end

# 単一整数表記 -> 16進数表記
def unit2hex(unit)
	sprintf("%08x", unit)
end

# 16進数表記 -> 単一整数表記
def hex2unit(hex)
	hex.to_i(16)
end

# 4等分して.で結合
def divide_quad(str)
	len = str.length / 4
	str.scan(Regexp.new(".{#{len}}")).join(".")
end

# サブネットマスクっぽいかどうかを判定する:
# 2進数変換し、正規表現/^1*0*$/にマッチするならサブネットマスクと考える。
def subnetmask?(unit)
	unit2binary(unit).match?(/^1*0*$/)
end

def subnetmask2cidr(str)

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
		address_max: dot2unit("127.255.255.255"),
	},
	{
		class: "B",
		address_max: dot2unit("191.255.255.255"),
	},
	{
		class: "C",
		address_max: dot2unit("223.255.255.255"),
	},
	{
		class: "D",
		address_max: dot2unit("239.255.255.255"),
	},
	{
		class: "E",
		address_max: dot2unit("255.255.255.255"),
	},
]
# プライベートアドレスレンジ
PrivateAddress = {
	"A": "10.0.0.0/8",
	"B": "172.16.0.0/12",
	"C": "192.168.0.0/16",
}

def parse_mask(mask)
	# CIDR表記 -> そのまま採用
	if mask.match(/^\d+$/) && mask.to_i(10) <= 32
		return mask
	end
	# サブネットマスク -> CIDRに直す

	if mask.match(/^\d+\.\d+\.\d+\.\d+$/)
		addrs = mask.split(".").map{ |s| s.to_i(10) }
		if addrs.all?{ |a| a <= 255 }
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
	unit = array.reduce(0){ |s,i| (s << 8) + i }
	address_class = AddressClass.find{ |d| unit <= d[:address_max] }
	binstr = unit2binary(unit)
	r = {
		dot:			dot,
		array:			array,
		integer:		unit,
		hex:			unit2hex(unit),
		bin:			binstr,
		binquad:		divide_quad(binstr),
		address_class:	address_class ? address_class[:class] : nil,
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
		r[:netmask_hex] = unit2hex(netmask)
		r[:netmask_bin] = unit2binary(netmask)
		r[:netmask_binquad] = divide_quad(r[:netmask_bin])
		r[:netmask] = unit2dot(netmask)
		network_int = unit & netmask
		r[:network_int] = network_int
		r[:network_dot] = unit2dot(network_int)
		r[:network] = r[:network_dot]
		broadcast = network_int | ((1 << (32 - cidr)) - 1)
		r[:broadcast_dot] = unit2dot(broadcast)
		if cidr < 31
			r[:first_host_dot] = unit2dot(network_int + 1)
			r[:last_host_dot] = unit2dot(broadcast - 1)
		end
		if cidr < 32
			r[:host_num] = broadcast - network_int - 1
		end
	end
	# like a mask?
	if subnetmask?(unit)
		r[:is_like_a_mask] = true
		r[:as_cidr] = unit2binary(unit).scan(/^1+/)[0].size
		r[:as_first_host_dot] = unit2dot(unit + 1)
		r[:as_last_host_dot] = unit2dot((1 << 32) - 2)
	end
	# check private address
	if pv
		PrivateAddress.each{ |klass, pa|
			a = parse_dot(pa, false)
			if a[:integer] == (unit & a[:netmask_int])
				r[:is_private] = klass
			end
		}
	end
	# check loopback
	r[:is_loopback] = unit == dot2unit("127.0.0.1")
	return r
end

str = ARGV[0].chomp.gsub(/\s/, "")

case
when parsed = parse_dot(str)
	puts JSON.pretty_unparse(parsed)
else
	puts "Invalid Arg: #{str}";
end
