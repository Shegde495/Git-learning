from celery import Celery

celery = Celery('tasks', broker='redis://localhost:6379/0')

@celery.task
def my_task():
    print('Running')
    print('Hello, world!')
    print('Hello, world statsh!')