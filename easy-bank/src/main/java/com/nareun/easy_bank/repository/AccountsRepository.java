package com.nareun.easy_bank.repository;

import com.nareun.easy_bank.model.Accounts;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountsRepository extends CrudRepository<Accounts,Long> {

    Accounts findByCustomerId(int customerId);
}
