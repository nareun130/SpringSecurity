package com.nareun130.easy_bank.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.nareun130.easy_bank.model.Customer;

@Repository // ~> DAO의 메서드에서 발생할 수 있는 unchecked exception -> DataAccessException으로 처리
public interface CustomerRepository extends CrudRepository<Customer, Long> {

    Optional<Customer> findByEmail(String email);
    
}
