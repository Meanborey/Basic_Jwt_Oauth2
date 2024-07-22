package com.samboleap.spring_jwt_daoauthentication.repo;

import com.samboleap.spring_jwt_daoauthentication.model.UserAccount;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

@Repository
@Mapper
public interface UserRepo {
    @Select("select * from useraccount where username like #{username}")
    UserAccount findByAllUsers(String username);
}
