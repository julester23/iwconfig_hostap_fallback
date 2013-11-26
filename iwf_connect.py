#!/usr/bin/python

import subprocess
import iwlistparse
import time
import datetime
import logging

class NetConfig(object):

	def __repr__(self):
		return self.SSID + ' ' + str(type(self))

	def run_commands(self, command_list, stop_on_error=True):
		no_errors = True
		for cmd in command_list:
			r = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdout, stderr) = r.communicate()
			logging.debug('Running %s, returned %s' % (cmd, r.returncode))
			if r.returncode != 0:
				no_errors = False
				if stop_on_error:
					logging.error("Error when running %s, returned %s" % (cmd, r.returncode))
					if stdout:
						logging.error("Stdout: %s" % stdout)
					if stderr:
						logging.error("Stderr: %s" % stderr)
					return no_errors
		return no_errors


class NetConfigHost(NetConfig):
	def __init__(self, iface='wlan0', SSID='HostAP', **kwargs):
		self.iface = iface
		#self.preup = ['ifconfig %s %s netmask %s up' % (self.iface, '192.168.2.1', '255.255.255.0') ]
		self.preup = [ 'ip link set %s up' % self.iface, 'ip addr add %s dev %s' % ('192.168.2.1/24', self.iface) ]
		self.postup = ['/etc/init.d/hostapd start', '/etc/init.d/dnsmasq start', '/etc/init.d/isc-dhcp-server start']
		self.down = [  'ip addr flush dev %s' % self.iface, 'ip link set  %s down' % self.iface ]
		self.status = 'Not connected'
		self.SSID = SSID
		self.last_attempt = None

	def connect(self):
		logging.info("Creating Host AP")
		success = self.run_commands(self.preup + self.postup)
		if success:
			self.status = 'Connected'
		self.last_attempt = datetime.datetime.utcnow()
		return success

	def disconnect(self):
		logging.info('Disconnecting from host mode')
		self.run_commands(
			['/etc/init.d/hostapd stop',
			'/etc/init.d/dnsmasq stop',
			'/etc/init.d/isc-dhcp-server stop'] + self.down, stop_on_error=False)
		self.status = 'Not connected'

	def last_activity(self):
		if self.last_attempt != None:
			return self.last_attempt
		else:
			#default to "a long time ago"
			return (datetime.datetime.utcnow() - datetime.timedelta(days=1))
		#return some datetime based on lighttpd access log modify timestamp


class NetConfigClient(NetConfig):
	def __init__(self, iface='wlan0', SSID=None, encryption=None, password=None):
		self.iface = iface
		self.preup = ['ip link set %s up' % self.iface ]
		self.postup = ['dhclient -v -pf /run/dhclient.%s.pid -lf /var/lib/dhcp/dhclient.%s.leases %s' % ((self.iface,) * 3)]
		self.down = [ 'ip addr flush dev %s' % self.iface, 'ip link set %s down' % self.iface ]
		self.SSID = SSID
		self.encryption = encryption
		self.password = password
		self.status = 'Not connected'
		self.last_attempt = None
	
	def _connect_WPA(self):
		success = self.run_commands(
			['iwconfig %s mode Managed' % self.iface,
			'/sbin/wpa_supplicant -s -B -P /var/run/wpa_supplicant.wlan0.pid -i wlan0 -D nl80211,wext -C /var/run/wpa_supplicant',
			'/sbin/wpa_cli -i %s add_network' % self.iface,
			'/sbin/wpa_cli -i %s set_network 0 ssid \"%s\"' % (self.iface, self.SSID),
			'/sbin/wpa_cli -i %s set_network 0 scan_ssid 1' % self.iface,
			'/sbin/wpa_cli -i %s set_network 0 key_mgmt WPA-PSK' % self.iface,
			'/sbin/wpa_cli -i %s set_network 0 psk \"%s\"' % (self.iface, self.password),
			'/sbin/wpa_cli -i %s enable_network 0' % self.iface,
		])
		if not success:
			return success
		
		wpa_timer = datetime.datetime.utcnow()
		TIMEOUT_WPA_HANDSHAKE = 5
		while (datetime.datetime.utcnow() - wpa_timer).seconds < TIMEOUT_WPA_HANDSHAKE:
			try:
				logging.debug('Verifying WPA handshake')
				extra = subprocess.check_output(('/sbin/wpa_cli -i %s status' % self.iface).split(' '))
				#logging.debug('checking wpa_cli status: %s' % extra)
				wpa_status = {}
				if 'wpa_state=' in extra:
					wpa_status = dict(tuple(line.split('=')) for line in extra.split('\n') if '=' in line)
				if wpa_status.get('wpa_state') == 'COMPLETED':
					success = True
					logging.info('wpa_state == COMPLETED')
					break
				else:
					success = False
					logging.info('wpa_state != COMPLETED for %s/%ss: %s' % ((datetime.datetime.utcnow() - wpa_timer).seconds, TIMEOUT_WPA_HANDSHAKE, wpa_status.get('wpa_state', 'error in parsing wpa_cli status output')))
			except subprocess.CalledProcessError, e:
				logging.warn('Failed to call wpa_cli status: %s' % e)
			time.sleep(1)
					
		return success
	
	def _connect_WEP(self):
		success = self.run_commands([
			'iwconfig %s mode Managed' % self.iface,
			'iwconfig %s essid %s'% (self.iface, self.SSID),
			'iwconfig %s key %s' % (self.iface, self.password),
		])
		return success

	def _connect_Open(self):
		success = self.run_commands([
			'iwconfig %s mode Managed' % self.iface,
			'iwconfig %s essid %s'% (self.iface, self.SSID),
		])
		return success


	def connect(self):
		logging.info("Connecting to network %s" % self.SSID)
		success = self.run_commands(self.preup)
		if not success:
			return success
		if self.encryption == 'WPA':
			success = self._connect_WPA()
		elif self.encryption == 'WEP':
			success = self._connect_WEP()
		elif self.encryption == 'Open':
			success = self._connect_Open()

		if success:
			success = self.run_commands(self.postup)
		if success:
			ip_addr = subprocess.check_output(['ip', 'addr', 'list', 'dev' , self.iface])
			if 'state UP' not in ip_addr:
				success = False
		if success:
			self.status = 'Connected'
		self.last_attempt = datetime.datetime.utcnow()
		return success

	def disconnect(self):
		logging.info("Disconnecting from network %s" % self.SSID)
		pids_to_kill = []
		#wpa_cli terminate seems to handle this fine: /var/run/wpa_supplicant.wlan0.pid:
		for pidfile in ['/run/dhclient.%s.pid' % self.iface]:
			try:
				pids_to_kill.append(open(pidfile).readline().strip())
			except IOError, e:
				logging.debug('Failed to open file %s: %s' % (pidfile, e))
			except AttributeError, e:
				logging.debug('Failed to use contents of file %s: %s' % (pidfile, e))
				
		self.run_commands(
			['wpa_cli -i %s terminate' % self.iface,
			'kill %s' % ' '.join(pids_to_kill)] + self.down, stop_on_error=False)
		self.status = 'Not connected'
		
	
	def get_IP(self):
		try:
			ip_addr = subprocess.check_output(['ip', 'addr', 'list', 'dev' , self.iface])
			for line in ip_addr:
				if 'inet' in line:
					ip_net = line.strip(' ').split(' ')[0]
					return ip_net.partition('/')[0]
		except subprocess.CalledProcessError:
			logging.error("Failed to run ip addr in get_IP")
			return None
		except IndexError:
			logging.error("Unable to extract IP from ip addr output")
			return None
			
	def get_router(self):
		try:
			if self.status in ['Connected']:
				for line in open('/var/lib/dhcp/dhclient.%s.leases' % self.iface):
					if 'option routers' in line:
						return line.strip(' ').split(' ')[2].rstrip(';')
		except IndexError:
			return None

def network_scan(iface='wlan0'):
	network_list = iwlistparse.run_iwlist_scanning()
	col_title = network_list[0]
	return [dict(zip(col_title, net)) for net in network_list[1:]]
	list
	#iwlist wlan0 scanning
			

def update_from_config(config_from_file, config_in_mem, net_type=NetConfigClient):
	purge_list = []
	for net in config_in_mem:
		if net.SSID not in config_from_file.keys():
			#Removed from config
			logging.debug("Marking for purge: %s" % net)
			if net.status == 'Connected':
				net.disconnect()
			purge_list.append(net)
		else:
			#Config changed
			if 'encryption' in dir(net) and 'password' in dir(net):
				if net.encryption != config_from_file[net.SSID].get('Encryption') or net.password != config_from_file[net.SSID].get('Password'):
					logging.debug("Config changed for: %s\nWas: %s %s\nIs: %s %s" % (net, net.encryption, net.password, config_from_file[net.SSID].get('Encryption'), config_from_file[net.SSID].get('Password')))
					if net.status == 'Connected':
						net.disconnect()
					net.encryption = config_from_file[net.SSID].get('Encryption')
					net.password = config_from_file[net.SSID].get('Password')
	#Purge the configs removed from config_from_file
	for p in purge_list:
		config_in_mem.remove(p)
	#config_in_mem = filter(lambda a: a.status != 'Purge', config_in_mem)

	#Add missing configs
	logging.debug('%s vs %s' % (config_from_file.keys(), [net.SSID for net in config_in_mem]))
	for net_SSID in config_from_file.keys():
		if net_SSID not in [net.SSID for net in config_in_mem]:
			logging.debug("Config added for: %s %s %s" % (net_SSID, config_from_file[net_SSID].get('Encryption'), config_from_file[net_SSID].get('Password')))
			config_in_mem.append(net_type(SSID=net_SSID, encryption=config_from_file[net_SSID].get('Encryption'), password=config_from_file[net_SSID].get('Password')))
	logging.debug("Config updated: %s" % config_in_mem)


def main():
	global iwf_networks
#	try:
#		import wifi_network_config1
#	except SyntaxError, e:
#		logging.error('Error in wifi_network_config.py: %s' % e)
#	except ImportError, e:
#		logging.warn('No config wifi_network_config.py')

	#Reset interfaces:
	tmp = NetConfigClient()
	tmp.disconnect()
	tmp = NetConfigHost()
	tmp.disconnect()
	del tmp

	last_connection = None
	#TIMEOUT_HOST_MODE: Timer for preventing a flapping host mode network
	TIMEOUT_HOST_MODE = 30
	#TIMEOUT_RECONNECT: Standoff timer for failed network connection attempts 
	# (disables re-attempting network connections which failed in the last TIMEOUT_RECONNECT seconds)
	TIMEOUT_RECONNECT = 30
	networks_configured = []
	network_fallback = [NetConfigHost()]
	while True:
		now = datetime.datetime.utcnow()
		try:
			logging.debug('importing iwf_networks.py')
			import iwf_networks
			iwf_networks = reload(iwf_networks)
		except SyntaxError, e:
			logging.error("Error in iwf_networks.py: %s" % e)
		except ImportError, e:
			logging.warn('No config iwf_networks.py')
		else:
			update_from_config(iwf_networks.host_aps, networks_configured)
			if 'fallback' in dir(iwf_networks):
				update_from_config(iwf_networks.fallback, network_fallback, net_type=NetConfigHost)

		#If statement for the following code which will reconfigure the wifi:
		# - we are in fallback HOST mode & it has been running for > TIMEOUT_HOST_MODE seconds*
		# - we are no longer 'Connected' to the last network we connected to
		# - we are running for the first time and therefore last_connection is None
		#
		# * ideally timeout is related to usage of the configuration screens:  make sure we don't punt 
		# someone out of the hostAP mode if in use (this could boot people out while trying to correct mistakes in the config)

		if (isinstance(last_connection, NetConfigHost) and (now - last_connection.last_activity()).seconds > TIMEOUT_HOST_MODE) or (isinstance(last_connection, NetConfig) and last_connection.status != 'Connected') or last_connection == None:
			networks_scanned = network_scan()
			logging.debug("Scanned: %s" % networks_scanned)
			#common_nets = set([item['Name'] for item in networks_known]).union(set([item['Name'] for item in networks_scanned]))
			for net in networks_configured + network_fallback:
				#logging.debug("Looking for: %s" % net)
				if net.SSID in [item['Name'] for item in networks_scanned]:
					if net.last_attempt == None or (now - net.last_attempt).seconds > TIMEOUT_RECONNECT:
						logging.debug("Attempting: %s" % net)
						if last_connection and last_connection.status == 'Connected':
							last_connection.disconnect()
						last_connection = net
						if net.connect():
							logging.info('Success: %s' % net)
							break
						else:
							net.disconnect()
							logging.warn('Failed to setup: %s' % net)
							
					else:
						logging.debug('Recent (%ss) failure with %s, not trying again yet' % ((now - net.last_attempt).seconds, net))
				elif isinstance(net, NetConfigHost):
					if last_connection != net:
						if last_connection and last_connection.status == 'Connected':
							last_connection.disconnect()
						logging.info('Fallback setup: %s' % net)
						last_connection = net
						net.connect()
					else:
						logging.debug('Already connected to fallback')
				else:
					logging.debug('Configured network %s not found in scanned networks' % net)
					
			
		else:
			pass
		logging.debug("Sleep 10")
		time.sleep(10)

		
if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG)
#	for net in network_scan():
#		print '%s %s' % (net['Name'], net['Encryption'])
	main()

'''
loop:	
	if ! connected_as_client && now() - host_ap_idle > hostap_timeout :
		scanned_networks = network_scan()
		target_list = union(scanned_networks,configured_networks)
		for target_net in target_list + host_ap:
			if now() - last_connect[target_net] > reconnect_timeout:
				connected_as_client = ?
				update last_connect
				attempt target_net
				record result
				if result == success:
					break
'''

# vim: set ts=4 sw=4:
