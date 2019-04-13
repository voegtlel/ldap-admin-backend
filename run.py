import os
from wsgiref.simple_server import make_server


def main():
    import server

    with make_server('localhost', 8000, server.app) as httpd:
        print("Server up at localhost:8000")
        httpd.serve_forever()


if __name__ == '__main__':
    import watchgod


    class PythonConfigWatcher(watchgod.DefaultDirWatcher):
        def should_watch_file(self, entry):
            return entry.name.endswith(('.py', '.pyx', '.pyd', '.yaml'))

    watchgod.run_process(os.getcwd(), main, watcher_cls=PythonConfigWatcher)
