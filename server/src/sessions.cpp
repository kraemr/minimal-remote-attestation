#include "../inc/sessions.hpp"
#include "../../common/encoding.h"
#include "../../common/common-types.h"


char* uuid(char out[UUID_STR_LEN]){
  uuid_t b;
  uuid_generate(b);
  uuid_unparse_lower(b, out);
  return out;
}


// generates a DevId, a {DEV_ID}.sqlite database is created
// This database houses Sessions
void createDevId() {
  
}

void createSession(){

}

void createSessionWithDevID(){

}

// better to pass by ref as ServerSession is "large"
void createSession( ServerSession* session ){

}

void updateSession( ServerSession* session ){

}

void deleteSession( const char* path ){

}