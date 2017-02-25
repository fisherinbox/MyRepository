#include<queue>
#include<boost\thread\mutex.hpp>
#include<boost\thread\condition_variable.hpp>
using namespace std;
extern void push_pcap_queue();
//using namespace boost;
template<typename Data> class concurrent_queue  
{  
private:  
    std::queue<Data> the_queue;  
    mutable boost::mutex the_mutex;  
    boost::condition_variable the_condition_variable;  
public:  
    void push(Data const& data)  
    {  
        boost::mutex::scoped_lock lock(the_mutex);  
        the_queue.push(data);  
        lock.unlock();  
        the_condition_variable.notify_one();  
    }  
    bool empty() const 
    {  
        boost::mutex::scoped_lock lock(the_mutex);  
        return the_queue.empty();  
    }  
    bool try_pop(Data& popped_value)  
    {  
        boost::mutex::scoped_lock lock(the_mutex);  
        if(the_queue.empty())  
        {  
            return false;  
        }  
           
        popped_value=the_queue.front();  
        the_queue.pop();  
        return true;  
    }  
   void wait_and_push_allitem_to_pcapqueue()  
    {  
        boost::mutex::scoped_lock lock(the_mutex);  
        while(the_queue.empty())  
        {  
            the_condition_variable.wait(lock);  
        }
		//pop����Ԫ�أ��� ��ӵ�pcap�ķ��Ͷ��У�Ȼ�������ͷ���
		push_pcap_queue();
    }  
    void wait_and_pop(Data& popped_value)  
    {  
        boost::mutex::scoped_lock lock(the_mutex);  
        while(the_queue.empty())  
        {  
            the_condition_variable.wait(lock);  
        }  
           
        popped_value=the_queue.front();  
        the_queue.pop();  
    }  
	void just_pop(Data& popped_value)
	{
		popped_value=the_queue.front();  
        the_queue.pop();
	}
	void get_front(Data& popped_value)
	{
		boost::mutex::scoped_lock lock(the_mutex); 
		popped_value=the_queue.front();  
	}
	size_t getSize()
	{
		return the_queue.size();
	}
};