#include "../inc/sessions.hpp"
#include "../../common/encoding.h"
#include "../../common/common-types.h"


char* uuid(char out[UUID_STR_LEN]){
  uuid_t b;
  uuid_generate(b);
  uuid_unparse_lower(b, out);
  return out;
}

void createSessionAndDevID(){

}

void createSessionWithDevID(){

}

// better to pass by ref as ServerSession is "large"
void createSessionFile( ServerSession* session ){

}

void updateSessionFile( ServerSession* session ){

}

void deleteSessionFile( const char* path ){

}