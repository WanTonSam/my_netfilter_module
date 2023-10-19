
class configure;    //前向声明

class RuleManager {
public:
    RuleManager(configure &conf) : config(conf){};
    void addRule();
    void modifyRule();
    void deleteRule();
    void query_rule();
private:
    configure &config;
    
};