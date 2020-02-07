import time, threading
import socket
import random
import queue

def pack_data_q(name,queryid,number):   #对域名name的查询打包，其中number表示重传机制中的第几次发包
    hexqueryid='%s'%(chr(queryid))
    hexnum='%s'%(chr(number))
    hoststr=''
    for x in name.split('.'):
        hoststr = hoststr+chr(len(x))+x 
    data = '%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (hexqueryid,hexnum,hoststr)
    return data #返回的是字符串



class Locallist(object):
    def __init__(self):
        self.dic = {}           #本机保存ip与域名对应关系的缓存
        self.buffer={}          #保存客户端请求相关的信息（请求包序号和地址，端口）
        self.s_time={}          #保存向服务器发送请求相关的信息（重传的次数和发包的时间）
        self.sem=1              #保护buffer和s_time的锁
        self.Local_Server='192.168.31.1'#'10.3.9.5'    #本地DNS服务器的ip，这里是北邮校园网的
        self.Client='127.0.0.1'         #客户端的ip（本机）
        self.Port=53            
        self.MaxWaitTime=2      #超时--最大等待时间
        self.qin=queue.Queue()  #接受请求的队列
        self.qout=queue.Queue() #接受本地DNS服务器回复的队列
        self.sockin=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #连接客户的socket
        self.sockin.bind((self.Client,self.Port))
        self.sockout=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)#连接服务器的socket
    
    def GetSem(self):       #得到buffer和s_time的使用权
        if(self.sem==1):
            self.sem=0
            return 1
        else:
            return 0

    def ReturnSem(self):    #归还buffer和s_time的使用权
        if(self.sem==0):
            self.sem=1
        else:
            print('ERROR:SEM')


    def Read_Config(self):              #从本机文件获取DNS条目
        configf = open('dnsconfig.txt', 'r')
        for line in configf.readlines():
            self.dic[(line.strip()).split(' ',1)[1]]=(line.strip()).split(' ',1)[0]
        configf.close()

    def Write_Config(self):             #将缓存写入文件
        wconfig=open('dnsconfig.txt','w')
        for key,value in self.dic.items():
            wconfig.write(value)
            wconfig.write(" ")
            wconfig.write(key)
            wconfig.write('\n')
        wconfig.close()


    def ExternQuery(self,name,queryid,number):    #向本地DNS服务器进行对name的第number次查询
        data=pack_data_q(name,queryid,number)
        print('EXTERNAL QUERY')
        self.sockout.sendto(bytes(data, encoding = "iso8859"),(self.Local_Server,53))
        msg=self.sockout.recvfrom(1024)           #接收返回包
        self.qout.put(msg)                        #放入待处理队列




    def timer(self,name,queryid,number,t0):         #计时器，超时了重传，一共有三次机会 
        t1=time.time()
        str_queryid=str(queryid)
        while(str_queryid in self.s_time and (t1-t0)<self.MaxWaitTime): #计时。超时或者收到正确的返回包时，跳出循环
            t1=time.time()
        
        while(self.GetSem()==0):
            pass
        
        if(str_queryid in self.s_time):     #如果情况为超时，按重传次数分类
            if(number==2):
                if((self.s_time[str_queryid])[0]==1):
                    self.s_time[str_queryid]=(2,time.time())
                    print("Timeout")
                    threading.Thread(target=self.timer, args=(name,queryid,3,(self.s_time[str_queryid])[1],)).start()
                    threading.Thread(target=self.ExternQuery, args=(name,queryid,2,)).start()


            elif(number==3):
                if((self.s_time[str_queryid])[0]==2):
                    self.s_time[str_queryid]=(3,time.time())
                    print("Timeout:2")
                    threading.Thread(target=self.timer, args=(name,queryid,4,(self.s_time[str_queryid])[1],)).start()
                    threading.Thread(target=self.ExternQuery, args=(name,queryid,3,)).start()

            elif(number==4):
                if((self.s_time[str_queryid])[0]==3):
                    self.buffer.pop(str_queryid)    #超时，将字典中和本请求相关的条目去除
                    self.s_time.pop(str_queryid)
                    print("Timeout:3,stop")          #停止重传
            
            
            self.ReturnSem()
            
            
        else:
            print('not timeout')        #不是超时的情况（收到正确回复）
            
            self.ReturnSem()
            
        

    def SendBack(self,msg,ip,addr):     #若缓存内有对应的条目，直接发回客户端，不用向本地DNS服务器询问
        strmsg=msg.decode(encoding='iso8859')
        length=len(strmsg)
        s1=strmsg[0:2]
        s2=strmsg[8:length]
        i=0
        ip4=['','','','']
        for x in ip.split('.'):
            ip4[i]=chr(int(x))
            i=i+1
        if(ip=='0.0.0.0'):  #“域名不存在”的情况
            data='%s\x81\x83\x00\x01\x00\x00%s\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xdd\x00\x04%s%s%s%s'%(s1,s2,ip4[0],ip4[1],ip4[2],ip4[3])
        else:
            data='%s\x81\x80\x00\x01\x00\x01%s\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xdd\x00\x04%s%s%s%s'%(s1,s2,ip4[0],ip4[1],ip4[2],ip4[3])
        b_data=bytes(data, encoding = "iso8859")
        self.sockin.sendto(b_data,addr)


    def ReceivePackin(self):        #不断接受来自客户端的包
        while(1):
            
            try:
                msg=self.sockin.recvfrom(1024)
                self.qin.put(msg)
            except:
                pass


    def LocalQuery(self,name):      #向本地的DNS条目查询
        if name in self.dic:
            if self.dic[name]=="0.0.0.0":
                print("Domain name doesn't exist")
                return (1,'0.0.0.0')
            else:
                print("Local:",self.dic[name])
                return (1,self.dic[name])
        else:
            return (0,'')
    

    def PackProcess_In(self):       #处理来自客户端的包
        while(1):
            if(not self.qin.empty()):   #从队列头拿出包
                got=self.qin.get()
                msgtodo=got[0]
                addr=got[1]

                if(not(msgtodo[3]==131) and msgtodo[5]==1 and msgtodo[7]==0):   #确认是请求
                    q_id=chr(msgtodo[0])+chr(msgtodo[1])     #q_id是字符串
                    q_name=''
                    i=12
                    while(msgtodo[i]!=0):
                        i2=i+1+msgtodo[i]
                        q_name=q_name+(msgtodo[i+1:i2]).decode(encoding='iso8859')+'.'
                        i=i2
                    q_name=q_name[0:len(q_name)-1]   #q_name就是要查询的域名
                    print("question is")
                    print(q_name)
                    q_result=self.LocalQuery(q_name) #得到的IP地址没有尾部的'.'(包括 0.0.0.0)

                    if(q_result[0]==1):              #本地有对应的DNS条目的情况          
                        threading.Thread(target=self.SendBack, args=(msgtodo,q_result[1],addr,)).start()
                    else:                            #本地没有对应的DNS条目：向本地DNS服务器发出请求
                        
                        while(self.GetSem()==0):
                            pass
                        
                        queryid=random.randint(0,99)        #queryid是int
                        while(str(queryid) in self.buffer):
                            queryid=random.randint(0,99)
                        str_queryid=str(queryid)
                        self.buffer[str_queryid]=(q_id,addr)        #将请求的信息存入字典
                        self.s_time[str_queryid]=(1,time.time())
                        
                        self.ReturnSem()
                        
                        threading.Thread(target=self.timer,args=(q_name,queryid,2,(self.s_time[str_queryid])[1],)).start()  #计时
                        threading.Thread(target=self.ExternQuery, args=(q_name,queryid,1,)).start()     #发出请求

                    
    def PackProcess_Out(self):          #处理来自本地DNS服务器的包
        while(1):
            if(not self.qout.empty()):
                got=self.qout.get()
                msgtodo=got[0]

                if(msgtodo[7]>=1):          #确认这是回复      
                    a_id=msgtodo[0]           #a_id和a_number不是字符串
                    a_number=msgtodo[1]

                    str_a_id=str(a_id)
                    
                    while(self.GetSem()==0):
                        pass
                    
                    if(not(msgtodo[3]==131)):       #收到的不是“域名不存在”
                        if((str_a_id in self.s_time) and (self.s_time[str_a_id])[0]==a_number): #确认这是某个请求对应的回复（检查序号和重传次数）
                            ip=str(msgtodo[-4])+'.'+str(msgtodo[-3])+'.'+str(msgtodo[-2])+'.'+str(msgtodo[-1])  #获得IP
                            r_name=''
                            i=12
                            while(msgtodo[i]!=0):
                                i2=i+1+msgtodo[i]
                                r_name=r_name+msgtodo[i+1:i2].decode(encoding='iso8859')+'.'
                                i=i2
                            r_name=r_name[0:len(r_name)-1]   #r_name是查询的域名
                            self.dic[r_name]=ip              #将结果存在缓存中
                            back=self.buffer[str_a_id]
                            back_id=back[0]
                            back_addr=back[1]
                            msgback=back_id+msgtodo[2:].decode(encoding='iso8859')
                            b_msgback=bytes(msgback, encoding = "iso8859")
                            self.sockin.sendto(b_msgback,back_addr)
                            self.buffer.pop(str_a_id)       #将字典中和本请求相关的条目去除
                            self.s_time.pop(str_a_id)
                            print('ANSWER:',r_name)
                            print('ID:',repr(bytes(back_id, encoding = "iso8859")),'--->',str_a_id)
                                         
                    else:           #若“域名不存在”
                        if((str_a_id in self.s_time) and (self.s_time[str_a_id])[0]==a_number):
                            back=self.buffer[str_a_id]
                            back_id=back[0]
                            back_addr=back[1]
                            msgback=back_id+msgtodo[2:].decode(encoding='iso8859')   
                            b_msgback=bytes(msgback, encoding = "iso8859") 
                            self.sockin.sendto(b_msgback,back_addr)
                            self.buffer.pop(str_a_id)   #将字典中和本请求相关的条目去除
                            self.s_time.pop(str_a_id)
                    
                    self.ReturnSem()
                          
    def WriteBack(self):        #定时更新本地缓存（若有必要也可以定时删除，此处就提一下）
        t0=time.time()
        while(1):
            t1=time.time()
            if(t1-t0>=15):
                self.Write_Config()
                t0=t1





Local=Locallist()
Local.Read_Config()
threading.Thread(target=Local.ReceivePackin).start()
threading.Thread(target=Local.PackProcess_In).start()
threading.Thread(target=Local.PackProcess_Out).start()
threading.Thread(target=Local.WriteBack).start()

