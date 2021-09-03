-- [origin]

select
	100.00 * sum(case
		when p_type like 'PROMO%'
			then l_extendedprice * (1 - l_discount)
		else 0
	end) / sum(l_extendedprice * (1 - l_discount)) as promo_revenue
from
	lineitem,
	part
where
	l_partkey = p_partkey
	and cast(l_shipdate as Date) >= date '1995-09-01'
	and cast(l_shipdate as Date) < date '1995-09-01' + interval '1' month 
  
-- [default] change join type

select
	100.00 * sum(case
		when p_type like 'PROMO%'
			then l_extendedprice * (1 - l_discount)
		else 0
	end) / sum(l_extendedprice * (1 - l_discount)) as promo_revenue
from
	lineitem 
	    left join part on l_partkey = p_partkey
where
	cast(l_shipdate as Date) >= date '1995-09-01'
	and cast(l_shipdate as Date) < date '1995-09-01' + interval '1' month 
  
