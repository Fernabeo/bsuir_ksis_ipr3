#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PRIZHOK 30
#define TIMEOUT_RAW_SOCKET 2000

typedef struct {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_Header;

unsigned short checksum(unsigned short *buffer, int size) {	//функция для вычисления контрольной суммы
    long sum=0;
    while (size>1) {
        sum+=*buffer++;
        size-=2;
    }
    if (size>0) sum+=*(unsigned char *)buffer;
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (unsigned short)(~sum);
}

int main() {
	SetConsoleOutputCP(65001);	//установка кириллицы в консоли
    SetConsoleCP(65001);
	LARGE_INTEGER timer_speed;	//переменная для частоты таймера
	QueryPerformanceFrequency(&timer_speed);	//узнаем частоту высокоточного таймера
	char command[256];	//строка для хранения вводимой команды
	while (1) {	//иммитация бесконечной работы командной строки
		printf("Command (\"0\" - exit)>>>");	//приглашение для ввода команды
		fgets(command,sizeof(command),stdin);	//ввод команды
		command[strcspn(command,"\r\n")]='\0';	//отсекание символов конца строки и вставка нулевого символа
		if (strcmp(command,"0")==0) return 0;	//если введен 0, то выход из программы
		if ((strncmp(command,"tracert ",8)!=0)||(strncmp(command,"tracert ",8)==0&&command[8]=='\0')) {
			printf("Неверный формат. Используйте: tracert [IP/доменное_имя]\n");	//проверка на соответствие формату команды
			continue;	//запуск нового прохода цикла
		}
		WSADATA wsaData;	//инициализация Winsock
		if (WSAStartup(MAKEWORD(2,2),&wsaData)!=0) {	//если неудача
			printf("Ошибка инициализации Winsock.\n");	//то сообщение о ошибке
			continue;	//и завершение работы текущей команды
		}
		struct sockaddr_in server_addr;	//структура для хранения данных о сервере
		memset(&server_addr,0,sizeof(server_addr));	//очистка данной структуры
		server_addr.sin_family=AF_INET;	//использование IPv4 данных
		struct addrinfo filter,*res=NULL;	//структуры для разрешения имен
		memset(&filter,0,sizeof(filter));	//очистка структуры
		filter.ai_family=AF_INET;	//для указания работы с IPv4
		if (getaddrinfo(command+8,NULL,&filter,&res)!=0) {	//попытка получить IP по имени
			printf("Не удается разрешить системное имя узла %s\n",command+8);	//сообщение о неудачной попытки
			WSACleanup();	//освобождение занятых ресурсов
			continue;	//завершение работы текущей команды
		}
		server_addr.sin_addr=((struct sockaddr_in *)res->ai_addr)->sin_addr; //запись полученного IP адреса в нужном формате в структуру адреса сервера
		freeaddrinfo(res);	//освобождение памяти
		char ip_string[16];	//строка для вывода IP адреса
		inet_ntop(AF_INET,&server_addr.sin_addr,ip_string,16);	//перевод IP адреса в строковое представление
		printf("\nТрассировка маршрута к %s [%s]\nс максимальным числом прыжков %d:\n\n",command+8,ip_string,MAX_PRIZHOK);	//вывод информации на экран				
		SOCKET raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);	//создание "сырого" сокета
		if (raw_socket==INVALID_SOCKET) {	//если ошибка создания
			printf("Ошибка создания сокета: %d. (Запустите консоль от имени Администратора!)\n",WSAGetLastError());	//вывод сообщения об ошибке
			WSACleanup();	//освобождение ресурсов
			continue;	//переход к вводу новой команды
		}
		int timeout=TIMEOUT_RAW_SOCKET;	//переменная для хранения значения таймаута
		if (setsockopt(raw_socket,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout))==SOCKET_ERROR) {	//если установка таймаута неуспешна
			printf("Ошибка настройки таймаута сокета.\n");	//вывод соответствующего сообщения
			closesocket(raw_socket);	//закрытие сырого сокета
			WSACleanup();	//освобождение ресурсов
			continue;	//переход к запуску новой команды
		}
		char send_buffer[sizeof(ICMP_Header)+32];	//буффер для отправки пакетов
		char answer_buffer[1024];	//буффер для приема данных
		ICMP_Header *temp_buffer=(ICMP_Header*)send_buffer;	//указатель для удобной работы со структурой в буффере
		memset(send_buffer,0,sizeof(send_buffer));	//очистка буффера
		temp_buffer->type=8;	//тип: эхо-запрос
		temp_buffer->code=0;	//код для эхо-запроса
		temp_buffer->id=(unsigned short)GetCurrentProcessId();	//уникальный id на случай, если будет несколько процессов
		memset(send_buffer+sizeof(ICMP_Header),'E',32);	//заполнение остального места в буффере любой информацией
		struct sockaddr_in answer_addr;	//структура для хранения информации об авторе ответа
		int answer_length=sizeof(answer_addr);	//длина данной структуры
		for (int ttl=1;ttl<=MAX_PRIZHOK;ttl++) {	//создаем внешний цикл для каждого маршрутизатора на пути
			setsockopt(raw_socket,IPPROTO_IP,IP_TTL,(char *)&ttl,sizeof(ttl));	//для каждого шага устанавливаем TTL (время жизни пакета)    
			char ip_marshrut[16]="";	//строка для хранения IP адреса промежуточного маршрутизатора
			int finish=0;    //переменная для информирования о достижении конечного сервера
			printf("%3d",ttl); //Вывод номера шага
			for (int packet=0;packet<3;packet++) {	//отправляем на каждом шагу по три пакета
				temp_buffer->seq=(ttl*10)+packet;	//уникальный номер для пакета
				temp_buffer->checksum=0;	//контрольная сумма
				temp_buffer->checksum=checksum((unsigned short *)send_buffer,sizeof(send_buffer));	//вычисление и запись контрольной суммы
				LARGE_INTEGER timer_start,timer_end;	//начало и окончание таймера
				QueryPerformanceCounter(&timer_start);	//засекаем начало работы
				sendto(raw_socket,send_buffer,sizeof(send_buffer),0,(struct sockaddr *)&server_addr,sizeof(server_addr));	//отправка пакета
				int kol_bytes=recvfrom(raw_socket,answer_buffer,sizeof(answer_buffer),0,(struct sockaddr *)&answer_addr,&answer_length);	//получение ответа и количества полученной информации
				QueryPerformanceCounter(&timer_end);	//засекаем конец работы
				double timer=(double)(timer_end.QuadPart-timer_start.QuadPart)*1000.0/timer_speed.QuadPart;	//вычисляем время работы
				int time_work=(int)timer;	//округляем до миллисекунд
				if (kol_bytes==SOCKET_ERROR)	//если ошибка получения
					printf("     *   ");	//пишим звездочку
				else {	//если успешный ответ
					if (time_work<1) printf("    <1 ms");	//выводим время ответа
						else printf("  %4d ms",time_work);
					inet_ntop(AF_INET,&answer_addr.sin_addr,ip_marshrut,16);	//получение IP-адреса ответа в виде строки
					ICMP_Header *temp_buffer=(ICMP_Header *)(answer_buffer+20);	//указатель на начало ICMP пакета (уход от заголовка)
					if (temp_buffer->type==0) finish=1;	//тип 0 ответа означает, что запрос достиг целевого сервера
				}
			}
			Sleep(100);	//пауза между отправками пакетов
			if (strlen(ip_marshrut)>0) {	//если строки с IP адресом ответа непустая
				char hostname[1024]="";	//строка для имени хоста
				if (getnameinfo((struct sockaddr*)&answer_addr,sizeof(answer_addr),hostname,sizeof(hostname),NULL,0,0)==0&&strcmp(hostname,ip_marshrut)!=0) //определение имени хоста по его IP
					printf("  %s [%s]\n",hostname,ip_marshrut);	//если имя есть, выводим имя и IP
				else printf("  %s\n",ip_marshrut);	//если имени нет, то выводим только IP
			} else printf("  Превышен интервал ожидания для запроса.\n");	//если IP нет, то превышен интервал ожидания
			if (finish) {	//если после очередного шага достигнут целевой сервер
				printf("\nТрассировка завершена.\n\n");	//вывод сообщения
				break;	//завершение работы
			}
		}
		closesocket(raw_socket);	//закрытие сырого сокета
		WSACleanup();	//освобождение ресурсов
    }
}