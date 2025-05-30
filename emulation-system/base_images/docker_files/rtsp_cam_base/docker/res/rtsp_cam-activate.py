import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import parse_qs

cam_port = 8554

# http://127.0.0.1/zm - base url form
def login_to_Zone_minder(session, url, username="", password=""):
	"""Log in to the Zone_minder admin panel."""
	URL = f"{url}/index.php?view=privacy"
	response = session.get(URL)
	if not response.ok:
		print("Failed to fetch login page.")
		return None

	soup = BeautifulSoup(response.text, "html.parser")
	# contentForm > input[type=hidden]:nth-child(1)
	CSRF_token_fld = soup.find('input', attrs={"type": "hidden", "name": "__csrf_magic"});
	CSRF_token = CSRF_token_fld.get('value')
	
	login_payload = {	"__csrf_magic": CSRF_token,
		"view": 'privacy',
		"action": 'privacy',
		"option": 1
		}
	response = session.post(f"{url}/index.php?", data=login_payload)
	if "view=console" not in response.url:
		print("Login failed.")
		return None
	return response


def add_monitor(session, url, RTSP_path=""):
	"""Add monitor for the RTSP cam."""
	# we know video width & height, let hardcode here:
	width=1280
	height=720
	response = session.get(f"{url}/index.php?view=monitor")
	if not response.ok:
		print("Failed to fetch monitor page.")
		return None
	print("monitor page OK")
	soup = BeautifulSoup(response.text, "html.parser")
	# as usual, find the CSRF token
	CSRF_token_fld = soup.find('input', attrs={"type": "hidden", "name": "__csrf_magic"});
	CSRF_token = CSRF_token_fld.get('value')
	# Compose setup data (scary):
	data = {
	'__csrf_magic': CSRF_token,
	'tab': 'general',
	'mid': '',
	'origMethod': '',
	'newMonitor[Name]': 'Monitor-1',
	'newMonitor[Notes]': '',
	'newMonitor[ServerId]': '',
	'newMonitor[Type]': 'Ffmpeg',
	'newMonitor[Function]': 'Mocord',
	'newMonitor[Enabled]': '1',
	'newMonitor[DecodingEnabled]': '1',
	'newMonitor[AnalysisFPSLimit]': '',
	'newMonitor[MaxFPS]': '',
	'newMonitor[AlarmMaxFPS]': '',
	'newMonitor[RefBlendPerc]': '6',
	'newMonitor[AlarmRefBlendPerc]': '6',
	'newMonitor[Path]': RTSP_path,
	'newMonitor[Method]': 'rtpRtsp',
	'newMonitor[Options]': '',
	'newMonitor[SecondPath]': '',
	'newMonitor[DecoderHWAccelName]': '',
	'newMonitor[DecoderHWAccelDevice]': '',
	'newMonitor[Colours]': '4',
	'newMonitor[Width]': width,
	'newMonitor[Height]': height,
	'dimensions_select': f'{width}x{height}',
	'newMonitor[Orientation]': 'ROTATE_0',
	'newMonitor[Deinterlacing]': '0',
	'newMonitor[StorageId]': '0',
	'newMonitor[SaveJPEGs]': '3',
	'newMonitor[VideoWriter]': '0',
	'newMonitor[OutputCodec]': '0',
	'newMonitor[Encoder]': 'auto',
	'newMonitor[OutputContainer]': '',
	'newMonitor[LabelFormat]': '%N - %d/%m/%y %H:%M:%S',
	'newMonitor[LabelX]': '0',
	'newMonitor[LabelY]': '0',
	'newMonitor[LabelSize]': '1',
	'newMonitor[ImageBufferCount]': '3',
	'newMonitor[MaxImageBufferCount]': '0',
	'newMonitor[WarmupCount]': '0',    'newMonitor[PreEventCount]': '5',
	'newMonitor[PostEventCount]': '5',
	'newMonitor[StreamReplayBuffer]': '0',
	'newMonitor[AlarmFrameCount]': '1',
	'newMonitor[ControlId]': '',
	'newMonitor[ControlDevice]': '',
	'newMonitor[ControlAddress]': 'user:port@ip',
	'newMonitor[AutoStopTimeout]': '',
	'newMonitor[TrackDelay]': '',
	'newMonitor[ReturnLocation]': '-1',
	'newMonitor[ReturnDelay]': '',
	'newMonitor[EventPrefix]': 'Event-',
	'newMonitor[SectionLength]': '600',
	'newMonitor[MinSectionLength]': '10',
	'newMonitor[FrameSkip]': '0',
	'newMonitor[MotionFrameSkip]': '0',
	'newMonitor[AnalysisUpdateDelay]': '0',
	'newMonitor[FPSReportInterval]': '100',
	'newMonitor[DefaultRate]': '100',
	'newMonitor[DefaultScale]': '0',
	'newMonitor[DefaultCodec]': 'auto',
	'newMonitor[SignalCheckPoints]': '0',
	'action': 'save'
}
	#print('payload',setup)
	# Parse the query string into a dictionary
	#data = parse_qs(setup)
	response = session.post(f"{url}/index.php?view=monitor", data=data)
	if ("index.php" not in response.url) or (response.status_code!=200) :
		print(f"Monitor setup failed. response.url={response.url} code=",response.status_code)
		return None
	else:
		print("Monitor setup OK.")
	return response



def activate(url, cam_ip, username="", password=""):
	"""Main function to activate RTSP cam."""
	global cam_port
	session = requests.Session()
	
	# Log in to Zone_minder
	if not login_to_Zone_minder(session, url, username, password):
		return 1
	print("Login OK")
	
	# Add monitor:
	RTSP_path = f"rtsp://{cam_ip}:{cam_port}/Cam001" # we're Cam001 at port 8554
	if not add_monitor(session, url, RTSP_path) :
		return 1
	
		
	print("RTSP cam activated and setup completed.")
	return 0


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Activate the RTSP cam.")
	parser.add_argument("url", help="The URL of the Zone_minder site.", type=str)
	parser.add_argument("cam_ip", help="The camera ip.", type=str)
	#parser.add_argument("admin", help="The administrative username.", type=str)
	#parser.add_argument("password", help="The administrative password.", type=str)
	args = parser.parse_args()
	exit(activate(args.url, args.cam_ip)) # we do not have user/password at the beginning
