# Global Variables share among modules

stop_me = False

user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
             'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'

default_headers = {'User-Agent': user_agent, 'Range': 'bytes=0-102400'}

ports_saved_to_file = False

process_targets_done = False   # scan coroutine will wait until process_targets_done

tasks_count = 0    # task counter
