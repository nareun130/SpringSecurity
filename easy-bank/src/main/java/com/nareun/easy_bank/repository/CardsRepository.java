package com.nareun.easy_bank.repository;

import com.nareun.easy_bank.model.Cards;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CardsRepository extends CrudRepository<Cards,Long> {
    List<Cards> findByCustomerId(int customerId);
}
