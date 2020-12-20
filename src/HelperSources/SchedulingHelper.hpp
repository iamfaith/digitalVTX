//
// Created by consti10 on 20.12.20.
//

#ifndef WIFIBROADCAST_SCHEDULINGHELPER_H
#define WIFIBROADCAST_SCHEDULINGHELPER_H

#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>

namespace SchedulingHelper{
    static void printCurrentThreadPriority(const std::string name){
        int which = PRIO_PROCESS;
        id_t pid = (id_t)getpid();
        int priority= getpriority(which, pid);
        std::cout<<name<<" has priority "<<priority<<"\n";
    }

    static void printCurrentThreadSchedulingPolicy(const std::string name){
        auto self=pthread_self();
        int policy;
        sched_param param;
        auto result= pthread_getschedparam(self,&policy,&param);
        assert(result==0);
        std::cout<<name<<" has policy "<<policy<<" and priority "<<param.sched_priority<<"\n";
    }

    static void setThreadParams(){
        auto self=pthread_self();
        int policy=SCHED_FIFO;
        sched_param param;
        param.sched_priority=sched_get_priority_max(policy);
        auto result= pthread_setschedparam(self,policy,&param);
        assert(result==0);
    }
}
#endif //WIFIBROADCAST_SCHEDULINGHELPER_H
